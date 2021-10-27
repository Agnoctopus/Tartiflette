i = 0;
c = 0;
while (i < 3) {
    c++;
    i++;
}

i = 0;
c = 0;
while (i < 3) {
    c++;
    if (i == 1)
        break;
    i++;
}

i = 0;
c = 0;
do {
    c++;
    i++;
} while (i < 3);

c = 0;
for(i = 0; i < 3; i++) {
    c++;
}

c = 0;
for(var j = 0; j < 3; j++) {
    c++;
}

var i, tab, a, b;

tab = [];
for(i in {x:1, y: 2}) {
    tab.push(i);
}

a = {x:2, y: 2, "1": 3};
b = {"4" : 3 };
Object.setPrototypeOf(a, b);
tab = [];
for(i in a) {
    tab.push(i);
}

/* non enumerable properties hide enumerables ones in the
   prototype chain */
a = {y: 2, "1": 3};
Object.defineProperty(a, "x", { value: 1 });
b = {"x" : 3 };
Object.setPrototypeOf(a, b);
tab = [];
for(i in a) {
    tab.push(i);
}

/* array optimization */
a = [];
for(i = 0; i < 10; i++)
    a.push(i);
tab = [];
for(i in a) {
    tab.push(i);
}

/* iterate with a field */
a={x:0};
tab = [];
for(a.x in {x:1, y: 2}) {
    tab.push(a.x);
}

/* iterate with a variable field */
a=[0];
tab = [];
for(a[0] in {x:1, y: 2}) {
    tab.push(a[0]);
}

/* variable definition in the for in */
tab = [];
for(var j in {x:1, y: 2}) {
    tab.push(j);
}

/* variable assigment in the for in */
tab = [];
for(var k = 2 in {x:1, y: 2}) {
    tab.push(k);
}

var i;
tab = [];
for(i in {x:1, y: 2, z:3}) {
    if (i === "y")
        continue;
    tab.push(i);
}

tab = [];
for(i in {x:1, y: 2, z:3}) {
    if (i === "z")
        break;
    tab.push(i);
}

var i, c;
c = 0;
L1: for(i = 0; i < 3; i++) {
    c++;
    if (i == 0)
        continue;
    while (1) {
        break L1;
    }
}

var i, a, s;
s = "";
for(i = 0; i < 3; i++) {
    a = "?";
    switch(i) {
    case 0:
        a = "a";
        break;
    case 1:
        a = "b";
        break;
    default:
        a = "c";
        break;
    }
    s += a;
}

var i, a, s;
s = "";
for(i = 0; i < 4; i++) {
    a = "?";
    switch(i) {
    case 0:
        a = "a";
        break;
    case 1:
        a = "b";
        break;
    case 2:
        continue;
    default:
        a = "" + i;
        break;
    }
    s += a;
}

try {
    throw "hello";
} catch (e) {
    assert(e, "hello", "catch");
    return;
}
