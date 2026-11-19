"use strict";
const { RevisionContract } = require("./src/chaincode/contract.cjs");
module.exports.contracts = [RevisionContract];
module.exports.RevisionContract = RevisionContract;
