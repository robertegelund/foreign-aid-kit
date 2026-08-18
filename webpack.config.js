const path = require("path")
const webpack = require("webpack")
const HtmlWebpackPlugin = require("html-webpack-plugin")
require("dotenv").config()

module.exports = {
    mode: "development",
    entry: {
        bundle: path.resolve(__dirname, "src/index.js"),
    },
    output: {
        path: path.resolve(__dirname, "dist"),
        filename: "[name][contenthash].js",
        clean:  true,
        assetModuleFilename: "[name][ext]",
    },
    devServer: {
        static: [
            { directory: path.resolve(__dirname, "dist") },
            { directory: path.resolve(__dirname, "data"), publicPath: "/data" },
            { directory: path.resolve(__dirname, "images"), publicPath: "/images" },
        ],
        port: 3000,
        open: true,
        hot: true,
        compress: true,
        historyApiFallback: true,
    },
    devtool: "source-map",
    module: {
        rules: [
            {
               test: /\.scss$/,
               use: ["style-loader", "css-loader", "sass-loader"] 
            },
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: {
                    loader: "babel-loader",
                    options: {
                        presets: ["@babel/preset-env"],
                    },
                },
            },
            {
                test: /\.(png|svg|jpg|jpeg|gif)$/i,
                type: "asset/resource"
            }
        ],
    },
    plugins: [
        new HtmlWebpackPlugin({
            title: "Foreign Aid Kit",
            filename: "index.html",
            template: "src/template.html"
        }),
        new webpack.DefinePlugin({
            "process.env.MAPBOX_API_KEY": JSON.stringify(process.env.MAPBOX_API_KEY),
        }),
    ]
}