function fuzz() {
var a = [1, 2, 3];
var my = new Array(["a", 1, 2, 3, "x", a]);
a = new Array(10);
a = new Array(1, 2);
a = [1, 2, 3];
a.length = 2;
a = [];
my.splice(2, 3);
my.flat();
my.forEach((x) => x.toString());
a.reverse();
a[1] = 10;
a[4] = 3;
a.shift();
a.unshift();
a = [1,2];
a.length = 5;
a[4] = 1;
a.length = 4;
a = [1,2];
a.push(3,4);
a.fill(1, 2);
a.fill(1, 2, 0);
a = [1,2,3,4,5];
Object.defineProperty(a, "3", { configurable: false });
err = false;
a.length = 2;
err = true;
}

fuzz();