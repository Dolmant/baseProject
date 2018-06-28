// @flow
import React from "react"
import {observer, inject} from "mobx-react"
import type {StoreType} from "types"
import {InjectedComponent} from "store"
import Grid from "@material-ui/core/Grid"
import "./home.less"
import classNames from "util/classNames"

declare var $;
declare var TweenLite;
declare var TimelineLite;
declare var Elastic;

type Props = {
};

type InjectedProps = {
    store: StoreType,
};

type State = {
};

@inject("store")
@observer
export default class Home extends InjectedComponent<Props, InjectedProps, State> {
    state = {
    }

    render() {
        return (
            <div className="homeNew">
            </div>
        )
    }
}
