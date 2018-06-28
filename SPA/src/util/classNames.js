export default function classNames(classes) {
    return Object.keys(classes).filter((name) => classes[name]).join(' ');
}
