function fuzz() {
parseInt("123");
parseInt("  123r");
parseInt("0x123");
parseInt("0o123");
parseFloat("0x1234");
parseFloat("Infinity");
parseFloat("-Infinity");
parseFloat("123.2");
parseFloat("123.2e3");
a.toExponential(0);
a.toPrecision(1);
a.toFixed(2);
}
fuzz();
