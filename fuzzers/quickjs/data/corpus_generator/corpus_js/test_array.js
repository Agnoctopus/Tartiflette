function fuzz() {
var a = [1, 2, 3];
a = new Array(10);
a = new Array(1, 2);
a = [1, 2, 3];
a.length = 2;
a = [];
a[1] = 10;
a[4] = 3;
a = [1,2];
a.length = 5;
a[4] = 1;
a.length = 4;
a = [1,2];
a.push(3,4);
a = [1,2,3,4,5];
Object.defineProperty(a, "3", { configurable: false });
err = false;
a.length = 2;
err = true;
}

fuzz();
