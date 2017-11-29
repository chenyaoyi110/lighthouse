/**
 * @license Copyright 2017 Google Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
'use strict';

const ByteEfficiencyAudit = require('./byte-efficiency-audit');
const esprima = require('esprima');

const IGNORE_THRESHOLD_IN_PERCENT = .1;
const IGNORE_THRESHOLD_IN_BYTES = 2048;

class UnminifiedJavaScript extends ByteEfficiencyAudit {
  /**
   * @return {!AuditMeta}
   */
  static get meta() {
    return {
      name: 'unminified-javascript',
      description: 'Unminified JavaScript',
      informative: true,
      helpText: 'Minify JavaScript to save network bytes.',
      requiredArtifacts: ['Scripts', 'devtoolsLogs'],
    };
  }

  /**
   * @param {string} scriptContent
   * @return {{minifiedLength: number, contentLength: number}}
   */
  static computeWaste(scriptContent, networkRecord) {
    const contentLength = scriptContent.length;
    let tokenLength = 0;
    let tokenLengthWithMangling = 0;

    const tokens = esprima.tokenize(scriptContent);
    for (const token of tokens) {
      tokenLength += token.value.length;
      // assume all identifiers could be reduced to a single character
      tokenLengthWithMangling += token.type === 'Identifier' ? 1 : token.value.length;
    }

    if (1 - tokenLength / contentLength < IGNORE_THRESHOLD_IN_PERCENT) return null;

    const totalBytes = ByteEfficiencyAudit.estimateTransferSize(networkRecord, contentLength,
      'script');
    const wastedRatio = 1 - (tokenLength + tokenLengthWithMangling) / (2 * contentLength);
    const wastedBytes = Math.round(totalBytes * wastedRatio);

    return {
      url: networkRecord.url,
      totalBytes,
      wastedBytes,
      wastedPercent: 100 * wastedRatio,
    };
  }

  /**
   * @param {!Artifacts} artifacts
   * @return {!Audit.HeadingsResult}
   */
  static audit_(artifacts, networkRecords) {
    const scriptsByUrl = artifacts.Scripts;

    const results = [];
    for (const [url, scriptContent] of scriptsByUrl.entries()) {
      const networkRecord = networkRecords.find(record => record.url === url);
      if (!networkRecord || !scriptContent) continue;

      const result = UnminifiedJavaScript.computeWaste(scriptContent, networkRecord);
      if (!result || result.wastedBytes < IGNORE_THRESHOLD_IN_BYTES) continue;
      results.push(result);
    }

    return {
      results,
      headings: [
        {key: 'url', itemType: 'url', text: 'URL'},
        {key: 'totalKb', itemType: 'text', text: 'Original'},
        {key: 'potentialSavings', itemType: 'text', text: 'Potential Savings'},
      ],
    };
  }
}

module.exports = UnminifiedJavaScript;
