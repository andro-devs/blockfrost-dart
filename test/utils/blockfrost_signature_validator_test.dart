import 'dart:convert';

import 'package:blockfrost_api/src/utils/blockfrost_signature_validator.dart';
import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

const maxToleranceSeconds = 60;

// --- Test Constants ---
const testSecret = 'TEST_SECRET';
const testPayload = '{"event":"test_event", "data": "content"}';

// Helper function to generate a valid signature for tests
String generateSignature(int timestamp, String payload, String secret) {
  final signaturePayload = '$timestamp.$payload';
  final key = utf8.encode(secret);
  final messageBytes = utf8.encode(signaturePayload);

  final hmac = Hmac(sha256, key);
  final digest = hmac.convert(messageBytes);
  return digest.toString();
}

void main() {
  group('Blockfrost Webhook Signature Validation', () {
    final int standardTimestamp = 1759917705;
    final validator = TestBlockfrostValidatorAccessor();

    // Generate a valid signature string for the standard time and payload
    final String validSignature = generateSignature(
      standardTimestamp,
      testPayload,
      testSecret,
    );

    // Signature header
    final String validHeader = 't=$standardTimestamp,v1=$validSignature';

    // --- SUCCESS CASE ---
    test('Should return true for a valid, recent signature', () {
      final result = validator.callValidateSignature(
        signatureHeader: validHeader,
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: standardTimestamp,
      );
      expect(result, isTrue);
    });

    // --- FAILURE CASES ---
    test(
        'Should return false if signatureHeader is malformed (missing t or v1)',
        () {
      // Case 1: Missing timestamp
      final result1 = validator.callValidateSignature(
        signatureHeader: 'v1=$validSignature',
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: standardTimestamp,
      );
      expect(result1, isFalse, reason: 'Should fail if "t" is missing');

      // Case 2: Missing signature
      final result2 = validator.callValidateSignature(
        signatureHeader: 't=$standardTimestamp',
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: standardTimestamp,
      );
      expect(result2, isFalse, reason: 'Should fail if "v1" is missing');
    });

    test('Should return false if timestamp format is invalid', () {
      final invalidHeader = 't=mywrongtimestamp,v1=$validSignature';
      final result = validator.callValidateSignature(
        signatureHeader: invalidHeader,
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: standardTimestamp,
      );
      expect(result, isFalse);
    });

    test(
        'Should return false if the signature does not match (wrong secret or payload)',
        () {
      // 1. Wrong Secret (Use a different secret to calculate the expected signature)
      final badSignature = generateSignature(
        standardTimestamp,
        testPayload,
        'my_wrong_secret',
      );
      final badHeader = 't=$standardTimestamp,v1=$badSignature';

      // Validate using the correct secret
      final result = validator.callValidateSignature(
        signatureHeader: badHeader,
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: standardTimestamp,
      );
      expect(result, isFalse);
    });

    test('Should return false if the timestamp is too old (replay attack)', () {
      final farFutureTime = standardTimestamp + maxToleranceSeconds + 1;

      final result = validator.callValidateSignature(
        signatureHeader: validHeader,
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: farFutureTime, // Inject current time far in the future
      );
      expect(result, isFalse);
    });

    test('Should return false if the timestamp is too far in the future', () {
      final farPastTime = standardTimestamp - maxToleranceSeconds - 1;
      final result = validator.callValidateSignature(
        signatureHeader: validHeader,
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: farPastTime,
      );
      expect(result, isFalse);
    });

    test('Should return true if time difference is exactly the tolerance limit',
        () {
      final toleranceLimitTime = standardTimestamp + maxToleranceSeconds;
      final result = validator.callValidateSignature(
        signatureHeader: validHeader,
        requestPayload: testPayload,
        secretAuthToken: testSecret,
        currentUnixTime: toleranceLimitTime,
      );
      expect(result, isTrue);
    });
  });
}
