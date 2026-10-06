function clamp(value, max) {
    if (value > max) return max;
    return value;
}

const large = values.filter(value => value > limit);
