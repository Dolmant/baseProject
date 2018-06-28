const merge = require("webpack-merge")
const baseConfig = require("./webpack.base.config")
const path = require("path")
const UglifyJsPlugin = require("uglifyjs-webpack-plugin")

module.exports = merge(baseConfig, {
    output: {
        filename: "bundled.js",
        path: path.resolve(__dirname, "dist"),
    },
    mode: "production",
    optimization: {
        minimizer: [new UglifyJsPlugin({sourceMap: false})],
    },
})
