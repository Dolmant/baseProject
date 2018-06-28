const merge = require("webpack-merge")
const baseConfig = require("./webpack.base.config")
const path = require("path")

module.exports = merge(baseConfig, {
    devtool: "inline-source-map",
    output: {
        filename: "bundled.js",
        path: path.resolve(__dirname, "dist"),
    },
    devServer: {
        inline: true,
        port: "3001",
    },
    watchOptions: {
        aggregateTimeout: 300,
        poll: 1000,
        ignored: /node_modules/,
    },
    mode: "development",
})
