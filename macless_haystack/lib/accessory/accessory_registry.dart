import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:logger/logger.dart';
import 'package:macless_haystack/accessory/accessory_model.dart';
import 'package:latlong2/latlong.dart';
import 'package:macless_haystack/findMy/find_my_controller.dart';
import 'package:macless_haystack/findMy/models.dart';
import 'package:flutter_settings_screens/flutter_settings_screens.dart';
import 'package:macless_haystack/preferences/user_preferences_model.dart';
import './secure_storage_ext.dart';

const accessoryStorageKey = 'ACCESSORIES';
const historyStorageKey = 'HISTORY';

class AccessoryRegistry extends ChangeNotifier {
  var _storage = const FlutterSecureStorage();
  List<Accessory> _accessories = [];
  bool loading = false;
  bool initialLoadFinished = false;

  var logger = Logger(
    printer: PrettyPrinter(methodCount: 0),
  );

  /// Creates the accessory registry.
  ///
  /// This is used to manage the accessories of the user.
  AccessoryRegistry() : super();

  /// A list of the user's accessories.
  UnmodifiableListView<Accessory> get accessories =>
      UnmodifiableListView(_accessories);

  /// Loads the user's accessories from persistent storage.
  Future<void> loadAccessories() async {
    loading = true;

    String? serialized;

    try {
      serialized = await _storage.read(key: accessoryStorageKey);
    } catch (e) {
      serialized = null;
    }
    
    if (serialized != null) {
      List accessoryJson = json.decode(serialized);
      List<Accessory> loadedAccessories =
          accessoryJson.map((val) => Accessory.fromJson(val)).toList();
      _accessories = loadedAccessories;
      clearInvalidAccessories(_accessories);
      if (_accessories.length != loadedAccessories.length) {
        _storeAccessories();
      }
    } else {
      _accessories = [];
    }
    await loadHistory();

    loading = false;

    notifyListeners();
  }

  set setStorage(FlutterSecureStorage s) {
    _storage = s;
  }

  Future<void> loadHistory() async {
    String? history = await _storage.read(key: historyStorageKey);
    if (history != null) {
      Map<String, dynamic> jsonDecoded = jsonDecode(history);
      for (var item in _accessories) {
        var currElement = jsonDecoded[item.id];
        if (currElement != null) {
          item.addLocationHistory(currElement);
        }
      }
    }
  }

  Future<Uint8List> _kdf_sha256(Uint8List Z, Uint8List secret, int keyLength) async {
    final shaDigest = SHA256Digest();

    var counter = 1;
    var output = Uint8List(0);

    while(output.length < keyLength) {
      shaDigest.reset();
      shaDigest.update(Z, 0, Z.length);
      var counterData = ByteData(4)..setUint32(0, counter);
      var counterDataBytes = counterData.buffer.asUint8List();
      shaDigest.update(counterDataBytes, 0, counterDataBytes.lengthInBytes);

      shaDigest.update(secret, 0, secret.lengthInBytes);

      Uint8List out = Uint8List(shaDigest.digestSize);
      shaDigest.doFinal(out, 0);

      output = Uint8List.fromList([...output,...out]);
      counter++;
    }
    return output.sublist(0,keyLength);
  }

  Future<FindMyKeyPair> generateNextKey(String b64Public, Uint8List symmetric, String accessoryId) async {
    BigInt bytesToBigInt(Uint8List bytes) => BigInt.parse(bytes.map((b) => b.toRadixString(16).padLeft(2,'0')).join(), radix: 16);

    Uint8List SK1 = await _kdf_sha256(symmetric,utf8.encode("update"),32);

    Uint8List antiTrack = await _kdf_sha256(SK1,utf8.encode("diversify"),72);
    Uint8List ui = antiTrack.sublist(0,36);
    Uint8List vi = antiTrack.sublist(36,72);

    final ECDomainParameters curveDomainParam = ECDomainParameters('secp224r1');

    BigInt bigUi = bytesToBigInt(ui);
    BigInt bigVi = bytesToBigInt(vi);
    BigInt bigInitPublic = bytesToBigInt(base64.decode(b64Public));
    BigInt bigPrivKey = ((bigInitPublic * bigUi) + bigVi) % curveDomainParam.n;
    // final Uint8List privKeyBytes = Uint8List.fromList( //convert BigInt to Uint8List
    //   [for (var v = bigPrivKey; v > BigInt.zero; v = v >> 8) (v & BigInt.from(0xff)).toInt()]
    //       .reversed
    //       .toList(),
    // );

    // Uint8List pubKey = (curveDomainParam.G * bigPrivKey)!.getEncoded(false).sublist(1,29); //extract X coordinate only

    ECPublicKey puKey = ECPublicKey(curveDomainParam.G * bigPrivKey,curveDomainParam);
    ECPrivateKey prKey = ECPrivateKey(bigPrivKey,curveDomainParam);

    final hashedKey = FindMyController.getHashedPublicKey(publicKey:puKey);
    final keyPair = FindMyKeyPair(puKey, hashedKey, prKey, DateTime.now(), -1);
    await _storage.write(key: hashedKey, value: keyPair.getBase64PrivateKey());
    await _storage.writeList(key: accessoryId, value: hashedKey);
    return keyPair;
  }

  Future<String> getSymmetricKeys(Iterable<Accessory> currentAccessories) async {
    if(currentAccessories.isEmpty) {
      return "";
    }

    final accessory = currentAccessories.first;
    final lastKey = (await _storage.read(key: accessory.id) ?? "").split(":");

    if(lastKey.first=="") {
      final out = base64Decode(await accessory.getAdvertisementKey()).map((a)=>a.toRadixString(16)).join();
      logger.d(out);
      return out;
    }
    return base64Decode(lastKey[1]).map((a)=>a.toRadixString(16)).join();
  }

  /// Fetches new location reports and matches them to their accessory.
  Future<int> loadLocationReports(
      Iterable<Accessory> currentAccessories) async {
    List<Future<List<FindMyLocationReport>>> runningLocationRequests = [];
    // request location updates for all accessories simultaneously
    String? url = Settings.getValue<String>(endpointUrl);
    List<String> b64StorageKeys = [];
    for (var i = 0; i < currentAccessories.length; i++) {
      var accessory = currentAccessories.elementAt(i);

      var keyPair =
          await FindMyController.getKeyPair(accessory.hashedPublicKey);

      List<FindMyKeyPair> hashedPublicKeys =
          await Stream.fromIterable(accessory.additionalKeys)
              .asyncMap((hashedPublicKey) =>
                  FindMyController.getKeyPair(hashedPublicKey))
              .toList();

      hashedPublicKeys.add(keyPair);
      if(accessory.symmetricKey.isNotEmpty) { //use symmetric key rotation
        Uint8List symmetric = base64Decode(accessory.symmetricKey);
        String b64Pub;
        int parsedTimestamp;

        String rawStorage = await _storage.read(key: accessory.id) ?? "";
        final lastKey = rawStorage.split(":");
        if(rawStorage.isEmpty) { //get from tag configuration
          logger.d("Empty flutter storage");
          b64Pub = await accessory.getAdvertisementKey();
          parsedTimestamp = int.tryParse(accessory.symmetricTimestamp) ?? DateTime.now().millisecondsSinceEpoch;
          await _storage.write(key: accessory.id, value: '$parsedTimestamp:$b64Pub'); 
        }
        else { //use from secure storage
          b64Pub = lastKey[1];
          parsedTimestamp = int.tryParse(lastKey[0])!;
        }

        int timeOffsetMinutes = Settings.getValue<int>(timeOffset)!;
        if(timeOffsetMinutes!=0) {
          parsedTimestamp+=(timeOffsetMinutes*60000); //convert timeOffsetMinutes to ms
          await _storage.write(key: accessory.id, value: '$parsedTimestamp:$b64Pub');
          logger.d(parsedTimestamp);
        }

        int rotateInterval = (int.tryParse(accessory.rotateInterval) ?? 15) * 60000;
        int maxSize = (Duration(days:7).inMilliseconds~/rotateInterval);
        int iterations = ((DateTime.now().millisecondsSinceEpoch-parsedTimestamp)~/rotateInterval); //rotateInterval in minutes
        
        if(iterations>0) {
          //accessory.symmetricTimestamp=currentTimestamp.toString(); //update to current timestamp
          //accessory.symmetricKeyPair.clear();
          for(int i = 0; i < iterations && i < maxSize; i++) {
            logger.d(i);
            FindMyKeyPair nextKey = await generateNextKey(b64Pub, symmetric,accessory.id);
            //accessory.symmetricKeyPair.add(nextKey);
            b64Pub = nextKey.getBase64AdvertisementKey();
          }
          final time = (DateTime.now().millisecondsSinceEpoch~/rotateInterval)*rotateInterval;
          await _storage.write(key: accessory.id, value: '$time:$b64Pub'); //store the last base64 encoded public key in secure storage
          // int totalSize = accessory.symmetricKeyPair.length;
          // if(totalSize > maxSize) { //1440/15 ad interval * 7 days = 672 max keys
          //   accessory.symmetricKeyPair = accessory.symmetricKeyPair.sublist(totalSize-maxSize); //remove oldest element at beginning
          // }
        }
        b64StorageKeys = await _storage.readList(key: accessory.id); //stores accessoryid mapped to List of hashedKey 
        final diff = b64StorageKeys.length - maxSize;
        if(diff > 0) {
          for(int i = 0; i < diff; i++) { //delete the hashedkey -> private key mapping
            _storage.delete(key: b64StorageKeys.elementAt(i));
          }
          b64StorageKeys = b64StorageKeys.sublist(diff);
          _storage.replaceList(key: accessory.id, value: b64StorageKeys);
        }
        final storageKeys = await Future.wait(b64StorageKeys.map(FindMyController.getKeyPair));
        hashedPublicKeys = [...hashedPublicKeys,...storageKeys];
      }
      var locationRequest =
          FindMyController.computeResults(hashedPublicKeys, url);
      runningLocationRequests.add(locationRequest);
    }
    var reportsForAccessories = await Future.wait(runningLocationRequests);
    int out = 0;
    Map<Accessory, Future<List<Pair<dynamic, dynamic>>>> historyEntries = {};
    for (var i = 0; i < currentAccessories.length; i++) {
      var accessory = currentAccessories.elementAt(i);
      var reports = reportsForAccessories.elementAt(i);
      out += reports.length;
      logger.i(
          '${reports.length} reports fetched for ${accessory.hashedPublicKey} in total');

      if (reports.where((element) => !element.isEncrypted()).isNotEmpty) {
        var lastReport =
            reports.where((element) => !element.isEncrypted()).first;
        var reportDate = (lastReport.timestamp ?? lastReport.published) ??
            DateTime.fromMicrosecondsSinceEpoch(0);
        if (accessory.datePublished != null &&
            reportDate.isAfter(accessory.datePublished!)) {
          accessory.datePublished = reportDate;
          accessory.lastLocation =
              LatLng(lastReport.latitude!, lastReport.longitude!);

          // Update last battery status
          accessory.lastBatteryStatus = lastReport.batteryStatus;
          accessory.hasChangedFlag = true;
        }
      }
      historyEntries[accessory] = fillLocationHistory(reports, accessory);
    }
    // Store updated lastLocation and datePublished for accessories
    _storeAccessories();

    _storeHistory(historyEntries);

    initialLoadFinished = true;
    notifyListeners();
    return Future.value(out);
  }

  Future<void> _storeHistory(
      Map<Accessory, Future<List<Pair<dynamic, dynamic>>>>
          historyEntries) async {
    Map<String, List<Pair<dynamic, dynamic>>> historyEntriesAsJson = {};
    for (var entry in historyEntries.entries) {
      Accessory key = entry.key;
      Future<List<Pair<dynamic, dynamic>>> future = entry.value;
      List<Pair<dynamic, dynamic>> result = await future;
      var nowMinusDays = DateTime.now().subtract(const Duration(days: 7));
      var upperDayLimit =
          DateTime(nowMinusDays.year, nowMinusDays.month, nowMinusDays.day);
      var filtered = result
          .where((element) => element.end.isAfter(upperDayLimit))
          .toList();
      if (filtered.length != result.length) {
        logger.i(
            '${result.length - filtered.length} history elements have been filtered out and will be deleted due to age.');
      }
      historyEntriesAsJson[key.id] = filtered;
    }
    //find all accessories not in list (inactive or single item refresh)
    accessories
        .where((a) => !historyEntriesAsJson.keys.toList().contains(a.id))
        .forEach((a) {
      historyEntriesAsJson[a.id] = a.locationHistory;
    });

    var historyJson = jsonEncode(historyEntriesAsJson);
    _storage.write(key: historyStorageKey, value: historyJson);
  }

  /// Stores the user's accessories in persistent storage.
  Future<void> _storeAccessories() async {
    List jsonList = _accessories.map(jsonEncode).toList();
    await _storage.write(key: accessoryStorageKey, value: jsonList.toString());
  }

  /// Adds a new accessory to this registry.
  void addAccessory(Accessory accessory) {
    Accessory? foundOne;
    for (var acc in _accessories) {
      if (accessory.hashedPublicKey == acc.hashedPublicKey) {
        foundOne = acc;
        break; // There is already one with this id
      }
    }
    if (foundOne != null) {
      _accessories.remove(foundOne);
    }

    _accessories.add(accessory);
    _storeAccessories();
    notifyListeners();
  }

  /// Removes [accessory] from this registry.
  void removeAccessory(Accessory accessory) {
    _accessories.remove(accessory);
    accessory.getHashedPublicKey().then((publicKey) {
      _storage.delete(key: publicKey);
    });

    _storage.readList(key: accessory.id).then((hashedKeys) {
      for(final String k in hashedKeys) {
        _storage.delete(key: k); //delete hashedKeys -> private mapping
      }
      _storage.writeList(key: accessory.id, value: null); //null deletes the key -> List hashkeys mapping
      _storage.delete(key: accessory.id); //remove last generated public key + timestamp map
    });
    
    _storeAccessories();
    notifyListeners();
  }

  Future<List<Pair<dynamic, dynamic>>> fillLocationHistory(
      List<FindMyLocationReport> reports, Accessory accessory) async {
    List<FindMyLocationReport> decryptedReports = [];
    //Decrypt only reports that are not already decrypted
    Set<String> hashes = {};
    int count = 0;
    //This will be achieved by saving the hash(payload) of all already decrypted reports
    for (var i = 0; i < reports.length; i++) {
      var currHash = reports[i].hash;
      if (!accessory.containsHash(currHash)) {
        accessory.addDecryptedHash(currHash);
        logger.d('Decrypting report $i of ${reports.length} with id $currHash');
        await reports[i].decrypt();
        decryptedReports.add(reports[i]);
      } else {
        count++;
      }

      hashes.add(currHash!);
    }
    logger.d(
        '${reports.length - count} reports decrypted. Decryption of $count reports skipped, because they are already fetched and decrypted.');
    //All hashes, that are not in the reports anymore can be deleted, because they are out of time
    accessory.removeOldHashes();
    //Sort by date
    decryptedReports.sort((a, b) {
      var aDate = a.timestamp ?? DateTime(1970);
      var bDate = b.timestamp ?? DateTime(1970);
      return aDate.compareTo(bDate);
    });

    //Update the latest timestamp
    if (decryptedReports.isNotEmpty) {
      var lastReport = decryptedReports[decryptedReports.length - 1];
      var oldTs = accessory.datePublished;
      var latestReportTS =
          lastReport.timestamp ?? lastReport.published ?? DateTime(1971);

      if (oldTs == null || oldTs.isBefore(latestReportTS)) {
        //only an actualization if oldTS is not set or is older than the latest of the new ones
        accessory.lastLocation =
            LatLng(lastReport.latitude!, lastReport.longitude!);
        accessory.datePublished = latestReportTS;

        //Update alway battery status
        accessory.lastBatteryStatus = lastReport.batteryStatus;

        accessory.hasChangedFlag = true;

        notifyListeners(); //redraw the UI, if the timestamp has changed
      }
    }

//add to history in correct order
    for (var i = 0; i < decryptedReports.length; i++) {
      FindMyLocationReport report = decryptedReports[i];
      if (report.longitude!.abs() <= 180 && report.latitude!.abs() <= 90) {
        accessory.addLocationHistoryEntry(report);
      } else {
        logger.d(
            'Report skipped, because of anomaly data (lat: ${report.latitude}, lon: ${report.longitude}, acc: ${report.accuracy})');
      }
    }
    _storeAccessories();
    return accessory.locationHistory;
  }

  /// Updates [oldAccessory] with the values from [newAccessory].
  void editAccessory(Accessory oldAccessory, Accessory newAccessory) {
    oldAccessory.update(newAccessory);
    _storeAccessories();
    notifyListeners();
  }

  void clearInvalidAccessories(List<Accessory> loadedAccessories) async {
    List<int> indicesToRemove = [];
    for (int i = 0; i < accessories.length; i++) {
      bool containsKey =
          await _storage.containsKey(key: accessories[i].hashedPublicKey);
      if (!containsKey) {
        // Invalid Element should be removed
        indicesToRemove.add(i);
      }
    }
    for (int index in indicesToRemove.reversed) {
      loadedAccessories.removeAt(index);
    }
  }

  void deleteData(Accessory accessory) {
    accessory.lastBatteryStatus = null;
    accessory.lastLocation = null;
    accessory.hashesWithTS.clear();
    accessory.datePublished = DateTime(1970);
    accessory.place = Future.value(null);
    accessory.locationHistory.clear();
    _removeHistoryEntry(accessory);
    _storeAccessories();
    notifyListeners();
  }

  Future<void> _removeHistoryEntry(Accessory accessoryToRemove) async {
    String? history = await _storage.read(key: historyStorageKey);
    if (history == null || history.isEmpty) {
      return;
    }
    Map<String, dynamic> historyMap = jsonDecode(history);

    historyMap.remove(accessoryToRemove.id);

    await _storage.write(key: historyStorageKey, value: jsonEncode(historyMap));
  }

  void saveOrderUpdates(List<Accessory> newOrder) {
    final Map<Accessory, int> positionMap = {
      for (int i = 0; i < newOrder.length; i++) newOrder[i]: i,
    };
    _accessories.sort((a, b) => positionMap[a]!.compareTo(positionMap[b]!));
    _storeAccessories();
  }
}
