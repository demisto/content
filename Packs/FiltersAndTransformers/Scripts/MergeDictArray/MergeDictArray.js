function is_object(o) {
      return o instanceof Object && !(o instanceof Array);
}

function merge_value(dst, src, key, conflict_strategy, overwrite_by_src, overwrite_by_dst) {
    if (overwrite_by_src.indexOf(key) >= 0) {
        return src;
    } else if (overwrite_by_dst.indexOf(key) >= 0) {
        return dst;
    }
    switch (conflict_strategy) {
        case 'destination':
            return dst;
        case 'source':
            return src;
        case 'merge':
            let dst_array = Array.isArray(dst) ? dst.concat() : (dst !== null ? [dst] : []);
            let src_array = Array.isArray(src) ? src : (src !== null ? [src] : []);
            src_array.forEach(v => {
                if (dst_array.indexOf(v) < 0) {
                    dst_array.push(v);
                }
            });
            if (dst_array.length == 1 && (!Array.isArray(src) || !Array.isArray(dst))) {
                return dst_array[0];
            } else if (dst_array.length >= 1) {
                return dst_array;
            }
            return dst !== null ? dst : src;
        default:
            throw 'Invalid conflict_strategy: ' + conflict_strategy;
    }
}

function set_object_value(obj, path, value, append, conflict_strategy, overwrite_by_src, overwrite_by_dst) {
    const root = obj;
    path.split('.').forEach((key, i, keys) => {
        if (!key) {
            throw path + ' has an emtpy node.';
        }else if (keys.length-1 === i) {
            if (!append || !(key in obj)) {
                obj[key] = value;
            } else {
                obj[key] = merge_value(obj[key], value, key, conflict_strategy, overwrite_by_src, overwrite_by_dst);
            }
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

function merge_object_value(dst, src, conflict_strategy, overwrite_by_src, overwrite_by_dst) {
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
                out[k] = merge_value(dst[k], sval, k, conflict_strategy, overwrite_by_src, overwrite_by_dst);
            }
        } else {
            out[k] = src[k];
        }
    }
    return out;
}

function merge_array(dst, src, kmap, out_key, appendable, conflict_strategy, overwrite_by_src, overwrite_by_dst) {
    dst = dst.concat();
    src.forEach(sval => {
        let merged = false;
        if (is_object(sval)) {
            dst.forEach((dval, index) => {
                if (contains_object_value(dval, sval, kmap)) {
                    if (out_key) {
                        dst[index] = set_object_value(dval, out_key, sval, true,
                                                      conflict_strategy, overwrite_by_src, overwrite_by_dst);
                    } else {
                        dst[index] = merge_object_value(dval, sval,
                                                        conflict_strategy, overwrite_by_src, overwrite_by_dst);
                    }
                    merged = true;
                }
            });
        }
        if (!merged && appendable) {
            dst.push(out_key ? {[out_key]: sval} : sval);
        }
    });
    return dst;
}

let dst_value = args.value;
const src_array = Array.isArray(args.merge_with) ? args.merge_with : [args.merge_with];
const key_map = make_keymap(args.mapping);
const appendable = args.appendable.toLowerCase() == 'true';
const conflict_strategy = args.conflict_strategy ? args.conflict_strategy : 'merge';
const overwrite_by_src = argToList(args.overwrite_by_source);
const overwrite_by_dst = argToList(args.overwrite_by_destination);

if (overwrite_by_src.filter((v) => overwrite_by_dst.indexOf(v) >= 0).length !==0 ){
    throw 'A key is conflict in overwrite_by_source and overwrite_by_destination.';
}
if (src_array && args.merge_with !== null) {
    if (args.array_path) {
        dst_value.forEach(v => {
            let dst_array = dq(v, args.array_path);
            let new_array;
            if (!Array.isArray(dst_array)) {
                new_array = merge_array([dst_array], src_array, key_map, args.out_key, appendable,
                                        conflict_strategy, overwrite_by_src, overwrite_by_dst);
                if (new_array.length == 1) {
                    new_array = new_array[0];
                }
            } else {
                new_array = merge_array(dst_array, src_array, key_map, args.out_key, appendable,
                                        conflict_strategy, overwrite_by_src, overwrite_by_dst);
            }
            set_object_value(v, args.out_path ? args.out_path : args.array_path, new_array, false,
                                        conflict_strategy, overwrite_by_src, overwrite_by_dst);
        });
    } else {
        dst_value = merge_array(dst_value, src_array, key_map, args.out_key, appendable,
                                conflict_strategy, overwrite_by_src, overwrite_by_dst);
        if (args.out_path) {
            dst_value = [set_object_value({}, args.out_path, dst_value, false,
                                          conflict_strategy, overwrite_by_src, overwrite_by_dst)];
        }
    }
}
return dst_value;
