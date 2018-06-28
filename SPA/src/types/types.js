export type StoreType = {
    URL: string,
    replaceURL: (string) => {},
    pushURL: (string) => {},
    navHome: () => {},
    isHome: boolean,
    pushAnchor: (string) => {},
}
