_extend = function (dst, src) {

  var srcs = [], i;
  if (typeof (src) == 'object') {
    srcs.push(src);
  }
  else if (typeof (src) == 'array') {
    for (i = src.length - 1; i >= 0; i--) {
      srcs.push(this._extend({}, src[i]));
          };
  }
  else {
    throw new Error("Invalid argument");
  }

  for (i = srcs.length - 1; i >= 0; i--) {
    for (var key in srcs[i]) {
      dst[key] = srcs[i][key];
    }
  };

  return dst;
}