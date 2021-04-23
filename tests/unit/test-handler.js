'use strict';

const chai = require('chai');
const expect = chai.expect;

var lambda = require('../../index');

describe('Test index.handler', function () {

    it('verifies that the lambda module was loaded', () => {
        expect(lambda).to.not.be.null;
    });
});
