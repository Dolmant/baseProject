// @flow
import React from "react"
import ReactDOM from "react-dom"
import {MuiThemeProvider, createMuiTheme} from "@material-ui/core/styles"
// import blue from "@material-ui/core/colors/blue"
// import red from "@material-ui/core/colors/red"
// import yellow from "@material-ui/core/colors/yellow"
import {Provider} from "mobx-react"
// Imports the global 'docReady'
import "./util/docReady"
import PageRouter from "./pages/pageRouter"
import Store from "store"
import "./main.less"

declare var docReady;

const theme = createMuiTheme({
    palette: {
        primary: {
            main: "#ffcc00",
            light: "#ffff50",
            dark: "#c79c00",
            // dark: will be calculated from palette.primary.main,
            // contrastText: will be calculated to contast with palette.primary.main
        },
        secondary: {
            main: "#ffffff",
            // dark: will be calculated from palette.secondary.main,
            // contrastText: "#ffcc00",
        },
        // error: will use the default color
    },
})

docReady(() => {
    const appTarget = document.getElementById("mount")
    if (appTarget) {
        ReactDOM.render(
            <Provider store={Store}>
                <MuiThemeProvider theme={theme}>
                    <div>
                        <PageRouter />
                        {/* <ReduxToastr
                            timeOut={4000}
                            newestOnTop={false}
                            preventDuplicates
                            position="top-left"
                            transitionIn="fadeIn"
                            transitionOut="fadeOut"
                            progressBar
                        /> */}
                    </div>
                </MuiThemeProvider>
            </Provider>,
            appTarget)
    }
})
