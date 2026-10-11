import { test } from '@oclif/test';
import axios from 'axios';
import { expect } from 'chai';

describe('Relative file path', () => {
  test
    .stdout()
    .command(['start', '--data', './test/data/envs/file.json'])
    .do(async () => {
      const result = await axios.get('http://localhost:3000/file');

      expect(result.data).to.contain('filecontent');
    })
    .finally(() => {
      process.emit('SIGINT');
    })
    .it(
      'should start mock on port 3000 and call GET /file and get the file with a relative path from the environment file',
      (context) => {
        expect(context.stdout).to.contain('Server started');
      }
    );

  test
    .stdout()
    .command(['start', '--data', './test/data/envs/file.json'])
    .do(async () => {
      const result = await axios.get('http://localhost:3000/testfile/1');

      expect(result.data).to.contain('filecontent');
    })
    .finally(() => {
      process.emit('SIGINT');
    })
    .it(
      'should start mock on port 3000 and call GET /testfile/1 and get a partially templated file when the helper is in the middle of the file name',
      (context) => {
        expect(context.stdout).to.contain('Server started');
      }
    );

  test
    .stdout()
    .command(['start', '--data', './test/data/envs/file.json'])
    .do(async () => {
      const result = await axios.get('http://localhost:3000/param2/file1');

      expect(result.data).to.contain('filecontent');
    })
    .finally(() => {
      process.emit('SIGINT');
    })
    .it(
      'should start mock on port 3000 and call GET /param2/file1 and get the file content with a relative templated path when it stays within the static base',
      (context) => {
        expect(context.stdout).to.contain('Server started');
      }
    );
});
