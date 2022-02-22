function is_object(o) {
      return o instanceof Object && !(o instanceof Array);
}

function set_object_value(obj, path, value) {
    const root = obj;
    path.split('.').forEach((key, i, keys) => {
        if (!key) {
            throw path + ' has an emtpy node.';
        }else if (keys.length-1 === i) {
            obj[key] = value;
        } else {
            if (!is_object(obj[key])) {
                obj[key] = {};
            }
            obj = obj[key];
        }
    });
    return root;
}

function get_object_value(obj, path) {
    // this returns 'undefined' for undefined properties unlike dq().
    for (const key of path.split('.')) {
        if (!is_object(obj)) {
            return undefined;
        }
        obj = obj[key];
    }
    return obj;
}

function make_keymap(mapping) {
    let kmap = {};
    mapping.split(',').map(x => x.trim()).forEach(x => {
        let vals = x.split(':');
        if (vals.length < 2) {
            throw 'Invalid key:value pairs in the mapping.';
        }
        let src_key = vals.shift().trim();
        let dst_key = vals.join(':').trim();
        kmap[dst_key] = src_key;
    });
    return kmap;
}

function contains_value(dval, sval) {
    if (dval === undefined || sval === undefined) {
        return false;
    }
    sval = Array.isArray(sval) ? sval : [sval];
    dval = Array.isArray(dval) ? dval : [dval];
    return sval.filter(sv => dval.filter(dv => sv == dv).length > 0).length == sval.length;
}

function contains_object_value(dval, sval, kmap) {
    if (!is_object(dval) || !is_object(sval)) {
        return false;
    }
    for (const dk in kmap) {
        const sk = kmap[dk];
        if (!contains_value(get_object_value(dval, dk), get_object_value(sval, sk))) {
            return false;
        }
    }
    return true;
}

function merge_object_value(dst, src) {
    if (!is_object(dst)) {
        throw 'Invalid object in destination value: ' + JSON.stringify(dst);
    }
    if (!is_object(src)) {
        throw 'Invalid object in source value: ' + JSON.stringify(src);
    }
    let out = Object.assign({}, dst);
    for (const k in src) {
        if (k in dst) {
            for (const sval of Array.isArray(src[k]) ? src[k] : [src[k]]) {
                if (Array.isArray(dst[k])) {
                    if (dst[k].indexOf(sval) < 0) {
                        out[k] = dst[k].concat(sval);
                    }
                } else {
                    if (dst[k] != sval) {
                        out[k] = [dst[k], sval];
                    }
                }
            }
        } else {
           out[k] = src[k];
        }
    }
    return out;
}

function merge_array(dst, src, kmap, out_key, appendable) {
    let out = dst.concat();
    src.forEach(sval => {
        let merged = false;
        if (is_object(sval)) {
            dst.forEach((dval, index) => {
                if (contains_object_value(dval, sval, kmap)) {
                    if (out_key) {
                        out[index] = set_object_value(dval, out_key, sval);
                    } else {
                        out[index] = merge_object_value(dval, sval);
                    }
                    merged = true;
                }
            });
        }
        if (!merged && appendable) {
            out.push(sval);
        }
    });
    return out;
}

let dst_value = args.value;
const src_array = Array.isArray(args.merge_with) ? args.merge_with : [args.merge_with];
const key_map = make_keymap(args.mapping);
const appendable = args.appendable.toLowerCase() == 'true';
if (src_array) {
    if (args.array_path) {
        dst_value.forEach(v => {
            let dst_array = dq(v, args.array_path);
            if (!Array.isArray(dst_array)) {
                throw 'dst_value.' + args.array_path + ' is not array.';
            }
            const new_array = merge_array(dst_array, src_array, key_map, args.out_key, appendable);
            set_object_value(v, args.out_path ? args.out_path : args.array_path, new_array);
        });
    } else {
        dst_value = merge_array(dst_value, src_array, key_map, args.out_key, appendable);
        if (args.out_path) {
            dst_value = [set_object_value({}, args.out_path, dst_value)];
        }
    }
}
return dst_value;