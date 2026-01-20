import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'dart:convert';

extension FlutterSecureStorageListExt on FlutterSecureStorage {
    Future<void> writeList({
      required String key,
      required String? value,
      IOSOptions? iOptions,
      AndroidOptions? aOptions,
      LinuxOptions? lOptions,
      WebOptions? webOptions,
      MacOsOptions? mOptions,
      WindowsOptions? wOptions,
    }) async {
      if (value == null) {
        await delete(
          key: '_$key',
          iOptions:iOptions,
          aOptions:aOptions,
          lOptions:lOptions,
          webOptions:webOptions,
          mOptions:mOptions,
          wOptions:wOptions,
        );
      } else {
        final currentJSON = await read(
          key: '_$key',
          iOptions:iOptions,
          aOptions:aOptions,
          lOptions:lOptions,
          webOptions:webOptions,
          mOptions:mOptions,
          wOptions:wOptions,
        );
        List<String> decodedList;
        if(currentJSON == null || currentJSON.isEmpty) {
          decodedList = <String>[];
        }
        else {
          final decoded = json.decode(currentJSON);
          decodedList = List.from(decoded);
        }
        decodedList.add(value);
        final newJson = json.encode(decodedList);
        await write(
          key: '_$key',
          value: newJson,
          iOptions:iOptions,
          aOptions:aOptions,
          lOptions:lOptions,
          webOptions:webOptions,
          mOptions:mOptions,
          wOptions:wOptions,
        );
      }
    }

    Future<void> replaceList({
      required String key,
      required List<String>? value,
      IOSOptions? iOptions,
      AndroidOptions? aOptions,
      LinuxOptions? lOptions,
      WebOptions? webOptions,
      MacOsOptions? mOptions,
      WindowsOptions? wOptions,
    }) async {
      if (value == null) {
        await delete(
          key: '_$key',
          iOptions:iOptions,
          aOptions:aOptions,
          lOptions:lOptions,
          webOptions:webOptions,
          mOptions:mOptions,
          wOptions:wOptions,
        );
      } else {
        final currentJSON = await read(
          key: '_$key',
          iOptions:iOptions,
          aOptions:aOptions,
          lOptions:lOptions,
          webOptions:webOptions,
          mOptions:mOptions,
          wOptions:wOptions,
        );
        List<String> decodedList;
        if(currentJSON == null || currentJSON.isEmpty) {
          decodedList = <String>[];
        }
        else {
          final decoded = json.decode(currentJSON);
          decodedList = List.from(decoded);
        }
        decodedList = value;
        final newJson = json.encode(decodedList);
        await write(
          key: '_$key',
          value: newJson,
          iOptions:iOptions,
          aOptions:aOptions,
          lOptions:lOptions,
          webOptions:webOptions,
          mOptions:mOptions,
          wOptions:wOptions,
        );
      }
    }

    Future<List<String>> readList({
      required String key,
      IOSOptions? iOptions,
      AndroidOptions? aOptions,
      LinuxOptions? lOptions,
      WebOptions? webOptions,
      MacOsOptions? mOptions,
      WindowsOptions? wOptions,
    }) async {
      final currentJSON = await read(
        key: '_$key',
        iOptions:iOptions,
        aOptions:aOptions,
        lOptions:lOptions,
        webOptions:webOptions,
        mOptions:mOptions,
        wOptions:wOptions,
      );
      if(currentJSON?.isEmpty ?? true) { //return empty list
        return <String> [];
      }
      final decoded = json.decode(currentJSON ?? "");
      List<String> decodedList = List.from(decoded);
      return decodedList;
    }
  }