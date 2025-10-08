import 'dart:convert';

import 'package:blockfrost_api/src/utils/signature_validator.dart';
import 'package:crypto/crypto.dart';

const int maxToleranceSeconds = 60;

/// Adapter class which implements the validator interface to validate the blockfrost webhook signature.
class BlockfrostSignatureValidator implements SignatureValidator {
  @override
  bool validate({
    required String signatureHeader,
    required String requestPayload,
    required String secretAuthToken,
  }) {
    return _validateSignature(
      signatureHeader: signatureHeader,
      requestPayload: requestPayload,
      secretAuthToken: secretAuthToken,
    );
  }
}

bool _validateSignature({
  required String signatureHeader,
  required String requestPayload, // JSON payload as raw string
  required String secretAuthToken,
  int? currentUnixTime,
}) {
  // Parse the timestamp and signature from the header
  String? timestampString;
  List<String> providedSignatures = [];

  final parts = signatureHeader.split(',');
  for (final part in parts) {
    final pair = part.trim().split('=');
    if (pair.length == 2) {
      final key = pair[0];
      final value = pair[1];
      if (key == 't') {
        timestampString = value;
      } else if (key == 'v1') {
        providedSignatures.add(value);
      }
    }
  }

  if (timestampString == null || providedSignatures.isEmpty) {
    print('Validation Failed: Missing timestamp (t) or (v1) signature.');
    return false;
  }

  final int timestamp;
  try {
    timestamp = int.parse(timestampString);
  } catch (e) {
    print('Validation Failed: Invalid timestamp format.');
    return false;
  }

  // Prepare the signature_payload (timestamp.payload)
  final signaturePayload = '$timestampString.$requestPayload';

  // Compute the expected signature (HMAC-SHA256)
  final key = utf8.encode(secretAuthToken);
  final messageBytes = utf8.encode(signaturePayload);

  final hmac = Hmac(sha256, key);
  final digest = hmac.convert(messageBytes);
  final expectedSignature = digest.toString();

  // Check for matching signature
  bool signatureMatch =
      providedSignatures.any((sig) => sig == expectedSignature);

  if (!signatureMatch) {
    print('Verification Failed: Signatures do not match.');
    print('Expected: $expectedSignature');
    print('Provided: $providedSignatures');
    return false;
  }

  // Check timestamp tolerance (prevent replay attacks)
  // Note: we might also inject time for testing purposes
  final currentTimestamp = currentUnixTime ??
      (DateTime.now().millisecondsSinceEpoch ~/ 1000); // Unix time in seconds

  print("currentTimestamp: $currentTimestamp");
  final timeDifference = (currentTimestamp - timestamp).abs();
  print("timeDifference: $timeDifference");

  if (timeDifference > maxToleranceSeconds) {
    print(
        'Validation Failed: Timestamp too old/far ($timeDifference s difference).');
    return false;
  }
  return true;
}

/// TESTING ACCESSOR: used only by unit test to access the private method
class TestBlockfrostValidatorAccessor {
  bool callValidateSignature({
    required String signatureHeader,
    required String requestPayload,
    required String secretAuthToken,
    required int currentUnixTime,
  }) {
    return _validateSignature(
      signatureHeader: signatureHeader,
      requestPayload: requestPayload,
      secretAuthToken: secretAuthToken,
      currentUnixTime: currentUnixTime,
    );
  }
}
