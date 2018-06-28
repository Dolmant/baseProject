const merge = require("webpack-merge")
const webpack = require("webpack") // eslint-disable-line import/no-extraneous-dependencies
const baseConfig = require("./webpack.base.config")
const path = require("path")

module.exports = merge(baseConfig, {
    output: {
        filename: "bundled.js",
        path: path.resolve(__dirname, "dist"),
    },
    mode: "staging",
    plugins: [
        new webpack.optimize.UglifyJsPlugin({
            sourceMap: false, // flip this to true and use source-map-explorer to investigate minified bundle size
        }),
    ],
})
