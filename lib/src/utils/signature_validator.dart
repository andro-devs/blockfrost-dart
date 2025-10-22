// The interface for the signature validation
const int defaultMaxToleranceSeconds = 600;

abstract class SignatureValidator {
  bool validate({
    required String requestPayload,
    required String signatureHeader,
    required String secretAuthToken,
    int maxToleranceSeconds,
  });
}
