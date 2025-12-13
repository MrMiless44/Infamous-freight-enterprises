describe("Server initialization", () => {
  test("should load configuration", () => {
    const config = require("../src/config");
    expect(config.getLogLevel()).toBeDefined();
  });

  test("should have development mode", () => {
    expect(process.env.NODE_ENV).toBeDefined();
  });
});
