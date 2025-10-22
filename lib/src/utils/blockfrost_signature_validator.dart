import 'dart:convert';

import 'package:blockfrost_api/src/utils/signature_validation_exception.dart';
import 'package:blockfrost_api/src/utils/signature_validator.dart';
import 'package:crypto/crypto.dart';

/// Adapter class which implements the validator interface to validate the blockfrost webhook signature.
class BlockfrostSignatureValidator implements SignatureValidator {
  @override
  bool validate({
    required String requestPayload,
    required String signatureHeader,
    required String secretAuthToken,
    int maxToleranceSeconds = defaultMaxToleranceSeconds,
  }) {
    return _validateSignature(
      requestPayload: requestPayload,
      signatureHeader: signatureHeader,
      secretAuthToken: secretAuthToken,
      maxToleranceSeconds: maxToleranceSeconds,
    );
  }
}

bool _validateSignature({
  required String requestPayload,
  required String signatureHeader,
  required String secretAuthToken,
  required int maxToleranceSeconds,
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
    throw SignatureValidationException(
      "Invalid signature header format.",
      header: signatureHeader,
      payload: requestPayload,
    );
  }

  final int timestamp;
  try {
    timestamp = int.parse(timestampString);
  } catch (e) {
    throw SignatureValidationException(
      "Invalid timestamp format.",
      header: signatureHeader,
      payload: requestPayload,
    );
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
    throw SignatureValidationException(
      "No signature matches the expected signature for the payload.",
      header: signatureHeader,
      payload: requestPayload,
    );
  }

  // Check timestamp tolerance (prevent replay attacks)
  // Note: currentUnixTime can be injected for testing purposes
  final currentTimestamp =
      currentUnixTime ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);
  final timeDifference = (currentTimestamp - timestamp).abs();
  if (timeDifference > maxToleranceSeconds) {
    throw SignatureValidationException(
      "Signature's timestamp is outside of the time tolerance.",
      header: signatureHeader,
      payload: requestPayload,
    );
  }
  return true;
}

/// TESTING ACCESSOR: used only by unit test to access the private method
class TestBlockfrostValidatorAccessor {
  bool callValidateSignature({
    required String requestPayload,
    required String signatureHeader,
    required String secretAuthToken,
    required int currentUnixTime,
    int maxToleranceSeconds = defaultMaxToleranceSeconds,
  }) {
    return _validateSignature(
      requestPayload: requestPayload,
      signatureHeader: signatureHeader,
      secretAuthToken: secretAuthToken,
      currentUnixTime: currentUnixTime,
      maxToleranceSeconds: maxToleranceSeconds,
    );
  }
}
