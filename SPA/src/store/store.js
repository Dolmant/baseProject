// @flow
import {configure, observable, action, computed} from "mobx"
import React from "react"

configure({enforceActions: true})

const URLGenerator = () =>
    // window.history.replaceState({}, 'Home', '/');
    window.location.pathname

export class InjectedComponent<Props, InjectedProps, State = void> extends React.Component<Props, State> {
    state: State;
    props: Props & InjectedProps;
}

class Store {
    @observable URL = URLGenerator()

    @computed get isHome(): boolean {
        return this.URL.startsWith("/home") || this.URL === "/"
    }

    @action
    replaceURL = (URL: string) => {
        if (URL.startsWith("/")) {
            this.URL = URL
            window.history.replaceState({}, "", this.URL)
        } else {
            console.log(`URL error, give URL without origin e.g. /resources: ${URL}`)
        }
    }

    @action
    pushURL = (URL: string) => {
        if (URL.startsWith("/")) {
            this.URL = URL
            window.history.pushState({}, "", this.URL)
        } else {
            console.log(`URL error, give URL without origin e.g. /resources: ${URL}`)
        }
    }

    @action
    pushAnchor = (anchor: string) => {
        const hash = this.URL.split("#")
        if (hash.length > 2 || hash.length === 0) {
            console.log(`Hash error, tried to split: ${this.URL}`)
            return null
        }
        window.location.hash = `#${anchor}`
        this.URL = `${hash[0]}#${anchor}`
        window.history.pushState({}, "", this.URL)
        return null
    }

    @action
    navHome = () => {
        this.URL = "/"
        window.history.pushState({}, "Home", this.URL)
    }
}

export default new Store()
