class SignatureValidationException implements Exception {
  final String message;
  final String header;
  final String payload;

  SignatureValidationException(
    this.message, {
    required this.header,
    required this.payload,
  });

  @override
  String toString() {
    return 'SignatureValidationException: $message\n'
        'Header: $header\n'
        'Payload: $payload';
  }
}
