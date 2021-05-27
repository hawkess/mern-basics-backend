const path = require("path");
const webpack = require("webpack");
const CWD = process.cwd();

const nodeExternals = require("webpack-node-externals");
const config = {
  name: "server",
  entry: [path.join(CWD, "./server/server.js")],
  target: "node",
  output: {
    path: path.join(CWD, "/dist/"),
    filename: "server.generated.js",
    publicPath: "/dist/",
    libraryTarget: "commonjs2",
  },
  externals: [nodeExternals()],
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: ["babel-loader"],
      },
    ],
  },
};

module.exports = config;
