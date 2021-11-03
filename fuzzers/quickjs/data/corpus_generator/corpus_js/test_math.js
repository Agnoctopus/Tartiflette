function fuzz() {
Math.floor(a);
Math.ceil(a);
Math.imul(0x12345678, 123);
Math.fround(0.1);
}
fuzz();
