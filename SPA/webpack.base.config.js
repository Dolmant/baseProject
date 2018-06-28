const path = require("path")
const webpack = require('webpack'); // eslint-disable-line
const ExtractTextPlugin = require("extract-text-webpack-plugin") // eslint-disable-line import/no-extraneous-dependencies
const WebpackBundleSizeAnalyzerPlugin = require('webpack-bundle-size-analyzer').WebpackBundleSizeAnalyzerPlugin; // eslint-disable-line
const CopyWebpackPlugin = require("copy-webpack-plugin") // eslint-disable-line import/no-extraneous-dependencies

const extractLess = new ExtractTextPlugin({
    filename: "styles.css",
})

module.exports = {
    entry: path.resolve(__dirname, "./src/main.js"),
    module: {
        rules: [
            {
                test: /\.woff(2)?(\?v=[0-9]\.[0-9]\.[0-9])?$/,
                use: "url-loader?limit=10000&mimetype=application/font-woff",
            },
            {
                test: /\.(ttf|eot|gif)(\?v=[0-9]\.[0-9]\.[0-9])?$/,
                use: "file-loader",
            },
            {
                test: /\.svg$/,
                loader: "svg-inline-loader",
            },
            {
                test: /\.js$/,
                use: "babel-loader",
            },
            {
                test: /\.css$/,
                use: ["style-loader", "css-loader"],
            },
            {
                test: /\.less$/,
                use: extractLess.extract({
                    use: [{
                        loader: "css-loader",
                    }, {
                        loader: "less-loader",
                    }],
                    fallback: "style-loader",
                }),
            },
            {
                test: /\.scss$/,
                use: extractLess.extract({
                    use: [{
                        loader: "css-loader",
                    }, {
                        loader: "sass-loader",
                    }],
                    fallback: "style-loader",
                }),
            },
        ],
    },
    plugins: [
        extractLess,
        new WebpackBundleSizeAnalyzerPlugin("./plain-report.txt"),
        new CopyWebpackPlugin([{from: "index.html", to: "index.html"}]),
    ],
    resolve: {
        extensions: [".js", ".less", "scss", ".svg"],
        alias: {
            assets: path.resolve(__dirname, "./assets"),
            pages: path.resolve(__dirname, "./src/pages"),
            components: path.resolve(__dirname, "./src/components"),
            store: path.resolve(__dirname, "./src/store/store.js"),
            types: path.resolve(__dirname, "./src/types/types.js"),
            util: path.resolve(__dirname, "./src/util"),
        },
    },
}
