// The interface for the signature validation
abstract class SignatureValidator {
  bool validate({
    required String signatureHeader,
    required String requestPayload,
    required String secretAuthToken,
  });
}
