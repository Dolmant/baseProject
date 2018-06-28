// @flow
import {observer, inject} from "mobx-react"
import React from "react"
import Home from "pages/home/home"
import type {StoreType} from "types"
import {InjectedComponent} from "store"

type Props = {
};
type InjectedProps = {
    store: StoreType,
};

@inject("store")
@observer
export default class PageRouter extends InjectedComponent<Props, InjectedProps> {
    route() {
        // Route based on URL
        switch (true) {
        default:
        case this.props.store.isHome:
            return (
                    <div>
                        <Home />
                    </div>
            )
        }
    }
    render() {
        return (
            <div>
                {this.route()}
            </div>
        )
    }
}
