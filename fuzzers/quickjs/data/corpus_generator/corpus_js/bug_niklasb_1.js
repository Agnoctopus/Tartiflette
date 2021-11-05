(function () {
    var map = new WeakMap();
    var x = { map };
    map.set(x, map);
    () => x.map;
})();
