// api/src/errors/index.js
class ServiceUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.status = 503;
    this.name = "ServiceUnavailableError";
  }
}
