function fuzz() {
    var str = new String("1337");
    var obj = new Int8Array(1337);
    obj.toString = () => str;
    var str2 = str;
    var obj2 = {};
    str2 = str2 + obj;
}
fuzz();
