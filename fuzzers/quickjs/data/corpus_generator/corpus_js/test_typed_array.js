function fuzz() {
var buffer, a, i, str;
a = new Uint8Array(4);
a[0] = -1;
a = new Int8Array(3);
a[0] = 255;
a = new Int32Array(3);
a[0] = Math.pow(2, 32) - 1;
a = new Uint8ClampedArray(4);
a[0] = -100;
a[1] = 1.5;
a[2] = 0.5;
a[3] = 1233.5;
buffer = new ArrayBuffer(16);
a = new Uint32Array(buffer, 12, 1);
a[0] = -1;
a = new Uint16Array(buffer, 2);
a[0] = -1;
a = new Float32Array(buffer, 8, 1);
a[0] = 1;
a = new Uint8Array(buffer);
str = a.toString();
a = new Uint8Array([1, 2, 3, 4]);
a.set([10, 11], 2);
a.map((x) => x * 2);
buffer = a.slice(1, 3);
a.sort();
a.copyWithin(3, 0, 3);
}

fuzz();