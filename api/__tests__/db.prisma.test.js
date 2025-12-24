describe("Prisma client export", () => {
  test("exports the client for named imports (and optional default)", () => {
    jest.resetModules();

    // Use the real module but rely on the global Prisma mock from jest.setup.js
    const prismaModule = jest.requireActual("../src/db/prisma");

    expect(prismaModule).toBeDefined();
    expect(prismaModule.prisma).toBeDefined();
    expect(prismaModule.default ?? prismaModule.prisma).toBe(
      prismaModule.prisma,
    );
    expect(typeof prismaModule.prisma.$disconnect).toBe("function");
  });
});
