function fuzz() {
var a;
a = String("abc");
a.length == 3;
a[1];
a.charCodeAt(1) == 0x62;
String.fromCharCode(65) == "A";
String.fromCharCode.apply(null, [65, 66, 67]);
a.charAt(1) == "b";
a.charAt(-1) == "";
a.charAt(3) == "";
a = "abcd";
a.substring(1, 3);
a = String.fromCharCode(0x20ac);
a.charCodeAt(0);
a = "\u{10ffff}";
a.length == 2;
a = "\u{dbff}\u{dfff}";
a.codePointAt(0);
String.fromCodePoint(0x10ffff);
"a".concat("b", "c");
"aaaa".split();
"aaaa".split("", 0);
}
fuzz();
