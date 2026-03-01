const CopyPlugin = require("copy-webpack-plugin");
// In webpack.plugins.js
module.exports = [
  new CopyPlugin({
    patterns: [
      {
        from: path.resolve(__dirname, "assets"), // Source folder
        to: path.resolve(__dirname, ".webpack/renderer/assets"), // Destination folder
      },
    ],
  }),
];
