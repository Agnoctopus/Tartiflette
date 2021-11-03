function fuzz() {
    const wm1 = new WeakMap(),
    wm2 = new WeakMap(),
    wm3 = new WeakMap();
    const o1 = {},
    o2 = function() {},
    o3 = window;

    wm1.set(o1, 37);
    wm1.set(o2, 'azerty');
    wm2.set(o1, o2);
    wm2.set(o3, undefined);
    wm2.set(wm1, wm2);

    wm1.get(o2);
    wm2.get(o2);
    wm2.get(o3);

    wm1.has(o2);
    wm2.has(o2);
    wm2.has(o3);

    wm3.set(o1, 37);
    wm3.get(o1);

    wm1.has(o1);
    wm1.delete(o1);
    wm1.has(o1);
}
fuzz();
