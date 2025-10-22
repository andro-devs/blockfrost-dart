import 'dart:convert';

import 'package:blockfrost_api/blockfrost_api.dart';
import 'package:crypto/crypto.dart';
import 'package:test/test.dart';

const maxToleranceSeconds = 600;

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
        requestPayload: testPayload,
        signatureHeader: validHeader,
        secretAuthToken: testSecret,
        currentUnixTime: standardTimestamp,
      );
      expect(result, isTrue);
    });

    // --- FAILURE CASES ---
    test(
        'Should throw SignatureValidationException if signatureHeader is malformed (missing t or v1)',
        () {
      // Case 1: Missing timestamp
      expect(
        () => validator.callValidateSignature(
          requestPayload: testPayload,
          signatureHeader: 'v1=$validSignature',
          secretAuthToken: testSecret,
          currentUnixTime: standardTimestamp,
        ),
        throwsA(
          predicate(
            (e) =>
                e is SignatureValidationException &&
                e.message.contains('Invalid signature header format.'),
            'SignatureValidationException with correct message',
          ),
        ),
        reason: 'Should throw exception for malformed header',
      );
    });

    test(
        'Should throw SignatureValidationException if timestamp format is invalid',
        () {
      final invalidHeader = 't=mywrongtimestamp,v1=$validSignature';
      expect(
          () => validator.callValidateSignature(
                requestPayload: testPayload,
                signatureHeader: invalidHeader,
                secretAuthToken: testSecret,
                currentUnixTime: standardTimestamp,
              ),
          throwsA(
            predicate(
              (e) =>
                  e is SignatureValidationException &&
                  e.message.contains('Invalid timestamp format.'),
              'SignatureValidationException with correct message',
            ),
          ),
          reason: 'Should throw exception for invalid timestamp');
    });

    test(
        'Should throw SignatureValidationException if the signature does not match',
        () {
      // 1. Wrong Secret (Use a different secret to calculate the expected signature)
      final badSignature = generateSignature(
        standardTimestamp,
        testPayload,
        'my_wrong_secret',
      );
      final badHeader = 't=$standardTimestamp,v1=$badSignature';

      // Validate using the correct secret
      expect(
          () => validator.callValidateSignature(
                requestPayload: testPayload,
                signatureHeader: badHeader,
                secretAuthToken: testSecret,
                currentUnixTime: standardTimestamp,
              ),
          throwsA(
            predicate(
              (e) =>
                  e is SignatureValidationException &&
                  e.message.contains(
                      'No signature matches the expected signature for the payload.'),
              'SignatureValidationException with correct message',
            ),
          ),
          reason: 'Should throw exception for not matching signatures');
    });

    test(
        'Should throw SignatureValidationException if the timestamp is too far in the future',
        () {
      final farFutureTime = standardTimestamp + maxToleranceSeconds + 1;
      print("$farFutureTime");

      expect(
          () => validator.callValidateSignature(
                requestPayload: testPayload,
                signatureHeader: validHeader,
                secretAuthToken: testSecret,
                currentUnixTime:
                    farFutureTime, // Inject current time far in the future
              ),
          throwsA(
            predicate(
              (e) =>
                  e is SignatureValidationException &&
                  e.message.contains(
                      'Signature\'s timestamp is outside of the time tolerance.'),
              'SignatureValidationException with correct message',
            ),
          ),
          reason: 'Should throw exception for not matching signatures');
    });

    test(
        'Should throw SignatureValidationException if the timestamp is too old (replay attack)',
        () {
      final farPastTime = standardTimestamp - maxToleranceSeconds - 1;
      print("$farPastTime");
      expect(
          () => validator.callValidateSignature(
                requestPayload: testPayload,
                signatureHeader: validHeader,
                secretAuthToken: testSecret,
                currentUnixTime: farPastTime,
              ),
          throwsA(
            predicate(
              (e) =>
                  e is SignatureValidationException &&
                  e.message.contains(
                      'Signature\'s timestamp is outside of the time tolerance.'),
              'SignatureValidationException with correct message',
            ),
          ),
          reason: 'Should throw exception for not matching signatures');
    });

    test('Should return true if time difference is exactly the tolerance limit',
        () {
      final toleranceLimitTime = standardTimestamp + maxToleranceSeconds;
      final result = validator.callValidateSignature(
        requestPayload: testPayload,
        signatureHeader: validHeader,
        secretAuthToken: testSecret,
        currentUnixTime: toleranceLimitTime,
      );
      expect(result, isTrue);
    });

    test(
        'Should return true for custom maxToleranceSeconds if time difference is exactly the tolerance limit',
        () {
      int customMaxToleranceSeconds = 60;
      final toleranceLimitTime = standardTimestamp + customMaxToleranceSeconds;
      final result = validator.callValidateSignature(
        requestPayload: testPayload,
        signatureHeader: validHeader,
        secretAuthToken: testSecret,
        currentUnixTime: toleranceLimitTime,
        maxToleranceSeconds: customMaxToleranceSeconds,
      );
      expect(result, isTrue);
    });
  });
}
