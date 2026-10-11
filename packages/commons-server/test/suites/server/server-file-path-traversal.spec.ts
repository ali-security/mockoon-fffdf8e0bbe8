import {
  BodyTypes,
  Environment,
  Route,
  ServerErrorCodes
} from '@mockoon/commons';
import { expect } from 'chai';
import { promises as fs } from 'fs';
import { get as httpGet } from 'http';
import { parse, relative, resolve } from 'path';
import { MockoonServer } from '../../../src';

async function getEnvironment(name: string): Promise<Environment> {
  const environmentJson = await fs.readFile(
    `./test/data/environments/${name}-env.json`,
    'utf-8'
  );

  return JSON.parse(environmentJson) as Environment;
}

// directory containing the environment file, base for relative file paths
const environmentDirectory = resolve('./test/data/environments');
// file located outside of the environment directory
const outsideFilePath = resolve('./test/data/plain.data');
// file system root ('/' on POSIX, the drive root on Windows)
const fileSystemRoot = parse(environmentDirectory).root;
// path of the file located outside of the environment directory, relative to the file system root
const outsideFilePathFromRoot = relative(fileSystemRoot, outsideFilePath);
// directory served with an absolute templated path and its sibling sharing the same name prefix
const publicDirectory = resolve('./test/data/public');
const relativeEscapeError =
  'Access to relative path outside of the allowed base directory';
const absoluteEscapeError =
  'Access to absolute path outside of the original static base directory';
const rootBaseError = 'Templated file path requires a non-root base directory';
const urlParamTemplate = "./{{urlParam 'filename'}}";
const queryParamTemplate = "./{{queryParam 'filename'}}";
// absolute static base directory followed by a templating helper
const absoluteTemplate = `${environmentDirectory}/{{queryParam 'filename'}}`;

const urlParamRequest = (filename: string) => ({ params: { filename } });
const queryParamRequest = (filename: string) => ({ query: { filename } });

describe('Server file path traversal protection', () => {
  let environment: Environment;

  const getSafeFilePath = (
    filePath: string,
    request?: any,
    serverEnvironmentDirectory: string | undefined = environmentDirectory
  ): string => {
    const server: any = new MockoonServer(environment, {
      environmentDirectory: serverEnvironmentDirectory
    });

    return server.getSafeFilePath(filePath, request);
  };

  const expectRejected = (
    filePath: string,
    request: any,
    errorMessage: string,
    serverEnvironmentDirectory: string | undefined = environmentDirectory
  ) => {
    const getPath = () =>
      getSafeFilePath(filePath, request, serverEnvironmentDirectory);

    expect(getPath).to.throw(errorMessage);
  };

  before(async () => {
    environment = await getEnvironment('test');
  });

  it('should resolve a non templated relative path from the environment directory', () => {
    const expected = resolve(environmentDirectory, 'test-env.json');

    expect(getSafeFilePath('./test-env.json')).to.equal(expected);
  });

  it('should allow escaping the environment directory when the path is not templated', () => {
    expect(getSafeFilePath('../plain.data')).to.equal(outsideFilePath);
  });

  it('should allow any absolute path when the path is not templated', () => {
    expect(getSafeFilePath(outsideFilePath)).to.equal(outsideFilePath);
  });

  it('should allow a templated relative path staying in the environment directory', () => {
    const request = urlParamRequest('test-env.json');
    const expected = resolve(environmentDirectory, 'test-env.json');

    expect(getSafeFilePath(urlParamTemplate, request)).to.equal(expected);
  });

  it('should allow a templated relative path to a sub directory of the environment directory', () => {
    const request = queryParamRequest('sub/folder/../file.txt');
    const expected = resolve(environmentDirectory, 'sub', 'file.txt');

    expect(getSafeFilePath(queryParamTemplate, request)).to.equal(expected);
  });

  it('should reject a templated relative path escaping the environment directory (url param)', () => {
    const request = urlParamRequest('../plain.data');

    expectRejected(urlParamTemplate, request, relativeEscapeError);
  });

  it('should reject a templated relative path escaping the environment directory (query param)', () => {
    const request = queryParamRequest('../plain.data');

    expectRejected(queryParamTemplate, request, relativeEscapeError);
  });

  it('should reject the advisory payload (leading slash and multiple parent folders)', () => {
    const request = urlParamRequest('/../../../../../../../../etc/passwd');

    expectRejected(urlParamTemplate, request, relativeEscapeError);
  });

  it('should reject a templated relative path escaping through a static sub folder', () => {
    const template = "./files/{{queryParam 'filename'}}";
    const request = queryParamRequest('../../plain.data');

    expectRejected(template, request, relativeEscapeError);
  });

  it('should reject a fully templated path resolving outside of the environment directory', () => {
    const template = "{{queryParam 'filename'}}";
    const request = queryParamRequest('../../../../../../etc/passwd');

    expectRejected(template, request, relativeEscapeError);
  });

  it('should reject a templated relative path to a sibling directory sharing the environment directory name prefix', () => {
    const request = queryParamRequest('../environments-secret/key.txt');

    expectRejected(queryParamTemplate, request, relativeEscapeError);
  });

  it('should not allow escaping the environment directory with backslashes', () => {
    const request = queryParamRequest('..\\plain.data');

    if (process.platform === 'win32') {
      expectRejected(queryParamTemplate, request, relativeEscapeError);
    } else {
      // backslashes are regular file name characters on POSIX systems
      const expected = resolve(environmentDirectory, '..\\plain.data');

      expect(getSafeFilePath(queryParamTemplate, request)).to.equal(expected);
    }
  });

  it('should allow a templated absolute path staying in its static base directory', () => {
    const request = queryParamRequest('test-env.json');
    const expected = resolve(environmentDirectory, 'test-env.json');

    expect(getSafeFilePath(absoluteTemplate, request)).to.equal(expected);
  });

  it('should reject a templated absolute path escaping its static base directory', () => {
    const request = queryParamRequest('../plain.data');

    expectRejected(absoluteTemplate, request, absoluteEscapeError);
  });

  it('should reject a templated absolute path escaping to the file system root', () => {
    const request = queryParamRequest('../../../../../../../../etc/passwd');

    expectRejected(absoluteTemplate, request, absoluteEscapeError);
  });

  it('should reject a templated absolute path to a sibling directory sharing the static base name prefix', () => {
    const request = queryParamRequest('../environments-secret/key.txt');

    expectRejected(absoluteTemplate, request, absoluteEscapeError);
  });

  it('should allow a templated file name prefix in the static base directory', () => {
    const template = `${environmentDirectory}/file-{{queryParam 'id'}}.json`;
    const request = { query: { id: 'abc' } };
    const expected = resolve(environmentDirectory, 'file-abc.json');

    expect(getSafeFilePath(template, request)).to.equal(expected);
  });

  it('should reject a templated file name prefix escaping the static base directory', () => {
    const template = `${environmentDirectory}/file-{{queryParam 'id'}}.json`;
    const request = { query: { id: 'x/../../../plain' } };

    expectRejected(template, request, absoluteEscapeError);
  });

  it('should reject a fully templated path resolving to an absolute path', () => {
    const template = "{{queryParam 'filename'}}";
    const request = queryParamRequest(outsideFilePath);

    expectRejected(template, request, rootBaseError);
  });

  it('should reject a templated absolute path escaping to a sibling directory sharing the static base name prefix (advisory payload)', () => {
    const template = `${publicDirectory}/{{queryParam 'name'}}`;
    const request = { query: { name: '../public_backup/secret.txt' } };

    expectRejected(template, request, absoluteEscapeError);
  });

  it('should reject a templated path whose static base directory is the file system root', () => {
    const request = queryParamRequest(outsideFilePathFromRoot);

    expectRejected("/{{queryParam 'filename'}}", request, rootBaseError);
    expectRejected(
      `${fileSystemRoot}{{queryParam 'filename'}}`,
      request,
      rootBaseError
    );
    expectRejected(
      "/{{queryParam 'filename'}}",
      queryParamRequest('etc/passwd'),
      rootBaseError
    );
  });

  it('should reject a templated relative path whose static base directory resolves to the file system root', () => {
    const template = `${'../'.repeat(64)}{{queryParam 'filename'}}`;
    const request = queryParamRequest(outsideFilePathFromRoot);

    expectRejected(template, request, rootBaseError);
  });

  it('should reject templated paths when the only allowed base directory is the file system root', () => {
    const request = queryParamRequest('test.data');

    expectRejected(queryParamTemplate, request, rootBaseError, fileSystemRoot);
    expectRejected(
      "{{queryParam 'filename'}}",
      request,
      rootBaseError,
      fileSystemRoot
    );
  });

  it('should reject a templated relative path escaping its static sub folder while staying in the environment directory', () => {
    const template = "./files/{{queryParam 'filename'}}";
    const request = queryParamRequest('../test-env.json');

    expectRejected(template, request, relativeEscapeError);
  });

  it('should reject a templated relative path escaping a nested static base when the environment directory is the file system root', () => {
    const template = "./static/{{queryParam 'filename'}}";
    const request = queryParamRequest('../static_secret.txt');

    expectRejected(template, request, relativeEscapeError, fileSystemRoot);
  });

  it('should allow a templated relative path staying in its static base when the environment directory is the file system root', () => {
    const template = "./static/{{queryParam 'filename'}}";
    const request = queryParamRequest('asset.txt');
    const filePath = getSafeFilePath(template, request, fileSystemRoot);

    expect(filePath).to.equal(resolve(fileSystemRoot, 'static', 'asset.txt'));
  });

  it('should allow a templated relative path staying in its static base directory located outside of the environment directory', () => {
    const template = "../{{queryParam 'filename'}}";
    const request = queryParamRequest('plain.data');

    expect(getSafeFilePath(template, request)).to.equal(outsideFilePath);
  });

  it('should reject a templated relative path escaping its static base directory located outside of the environment directory', () => {
    const template = "../{{queryParam 'filename'}}";
    const request = queryParamRequest('../../plain.data');

    expectRejected(template, request, relativeEscapeError);
  });

  it('should allow a templated relative path when the helper is in the middle of the file name', () => {
    const template = "./static/file{{queryParam 'name'}}.json";
    const request = { query: { name: '1' } };
    const expected = resolve(environmentDirectory, 'static', 'file1.json');

    expect(getSafeFilePath(template, request)).to.equal(expected);
  });

  it('should allow a templated absolute path with backslashes when the helper is in the middle of the file name', () => {
    const template = `${publicDirectory}\\file{{queryParam 'name'}}.json`;
    const request = { query: { name: '1' } };
    const expected = resolve(publicDirectory, 'file1.json');

    expect(getSafeFilePath(template, request)).to.equal(expected);
  });

  it('should reject a templated absolute path escaping its static base when the helper is in the middle of the file name', () => {
    const template = `${publicDirectory}/file{{queryParam 'name'}}.json`;
    const request = { query: { name: '/../../secret' } };

    expectRejected(template, request, absoluteEscapeError);
  });

  it('should resolve a relative environment directory before detecting path traversal', () => {
    const relativeDir = './test/data/environments';
    const request = urlParamRequest('test-env.json');
    const expected = resolve(environmentDirectory, 'test-env.json');
    const filePath = getSafeFilePath(urlParamTemplate, request, relativeDir);

    expect(filePath).to.equal(expected);
    expectRejected(
      urlParamTemplate,
      urlParamRequest('../plain.data'),
      relativeEscapeError,
      relativeDir
    );
  });

  it('should use the current working directory when the environment directory is empty', () => {
    const request = urlParamRequest('test/data/plain.data');
    const filePath = getSafeFilePath(urlParamTemplate, request, '');

    expect(filePath).to.equal(outsideFilePath);
    expectRejected(
      urlParamTemplate,
      urlParamRequest('../plain.data'),
      relativeEscapeError,
      ''
    );
  });

  it('should use the current working directory when no options are provided', () => {
    const server: any = new MockoonServer(environment);
    const request = urlParamRequest('test/data/plain.data');
    const filePath = server.getSafeFilePath(urlParamTemplate, request);
    const getPath = () =>
      server.getSafeFilePath(urlParamTemplate, urlParamRequest('../x.data'));

    expect(filePath).to.equal(outsideFilePath);
    expect(getPath).to.throw(relativeEscapeError);
  });
});

describe('Server file serving path traversal', () => {
  const port = 3020;
  const errors: string[] = [];
  let server: MockoonServer;

  const fileRoute = (
    baseRoute: Route,
    endpoint: string,
    filePath: string
  ): Route => ({
    ...baseRoute,
    uuid: `file-route-${endpoint}`,
    endpoint,
    responses: [
      {
        ...baseRoute.responses[0],
        uuid: `file-route-response-${endpoint}`,
        bodyType: BodyTypes.FILE,
        filePath,
        sendFileAsBody: true
      }
    ]
  });

  const getResponseBody = (path: string): Promise<string> =>
    new Promise<string>((resolvePromise, reject) => {
      const url = `http://localhost:${port}${path}`;
      const clientRequest = httpGet(url, (response) => {
        let body = '';

        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          body += chunk;
        });
        response.on('end', () => {
          resolvePromise(body);
        });
      });

      clientRequest.on('error', reject);
    });

  before(async () => {
    const environment = await getEnvironment('test');
    const baseRoute = environment.routes[0];
    const fileRoutes: Route[] = [
      fileRoute(baseRoute, 'relative/:filename', urlParamTemplate),
      fileRoute(baseRoute, 'query', queryParamTemplate),
      fileRoute(baseRoute, 'absolute', absoluteTemplate),
      fileRoute(baseRoute, 'static', '../plain.data'),
      fileRoute(baseRoute, 'root', "/{{queryParam 'filename'}}"),
      fileRoute(baseRoute, 'sub', "./sub/{{queryParam 'filename'}}")
    ];

    environment.port = port;
    environment.routes = fileRoutes;
    environment.rootChildren = fileRoutes.map((route) => ({
      type: 'route' as const,
      uuid: route.uuid
    }));

    server = new MockoonServer(environment, { environmentDirectory });

    // record the serving errors (unhandled 'error' events would crash mocha)
    server.on('error', (errorCode, originalError) => {
      errors.push(`${errorCode}: ${originalError?.message}`);
    });

    await new Promise<void>((resolvePromise) => {
      server.on('started', () => {
        resolvePromise();
      });
      server.start();
    });
  });

  after(async () => {
    await new Promise<void>((resolvePromise) => {
      server.on('stopped', () => {
        resolvePromise();
      });
      server.stop();
    });
  });

  it('should serve a file from the environment directory with a templated relative path', async () => {
    const body = await getResponseBody('/relative/test-env.json');

    expect(body).to.contain('Test env');
  });

  it('should not serve a file outside of the environment directory with an encoded url param traversal', async () => {
    const body = await getResponseBody('/relative/..%2Fplain.data');

    expect(body).to.contain('Error while serving the content');
    expect(body).to.contain(relativeEscapeError);
    expect(body).not.to.contain('plainTest');
  });

  it('should not serve system files with the advisory payload', async () => {
    // enough parent folders to reach the file system root from any directory
    const payload = `${'%2F..'.repeat(16)}%2Fetc%2Fpasswd`;
    const body = await getResponseBody(`/relative/${payload}`);

    expect(body).to.contain(relativeEscapeError);
    expect(body).not.to.contain('root:');
  });

  it('should not serve a sibling directory sharing the environment directory name prefix', async () => {
    const payload = '..%2Fenvironments-secret%2Fkey.txt';
    const body = await getResponseBody(`/relative/${payload}`);

    expect(body).to.contain(relativeEscapeError);
  });

  it('should not serve a file outside of the environment directory with a query param traversal', async () => {
    const body = await getResponseBody('/query?filename=../plain.data');

    expect(body).to.contain(relativeEscapeError);
    expect(body).not.to.contain('plainTest');
  });

  it('should serve a file from the static base directory with a templated absolute path', async () => {
    const body = await getResponseBody('/absolute?filename=test-env.json');

    expect(body).to.contain('Test env');
  });

  it('should not serve a file outside of the static base directory with a templated absolute path', async () => {
    const body = await getResponseBody('/absolute?filename=../plain.data');

    expect(body).to.contain(absoluteEscapeError);
    expect(body).not.to.contain('plainTest');
  });

  it('should still serve a file outside of the environment directory when the path is not templated', async () => {
    const body = await getResponseBody('/static');

    expect(body).to.contain('plainTest');
  });

  it('should not serve any file of the file system with a templated path based on the file system root', async () => {
    const filename = encodeURIComponent(outsideFilePathFromRoot);
    const body = await getResponseBody(`/root?filename=${filename}`);

    expect(body).to.contain(rootBaseError);
    expect(body).not.to.contain('plainTest');
  });

  it('should not serve a file of the environment directory outside of the static sub folder of a templated relative path', async () => {
    const body = await getResponseBody('/sub?filename=../test-env.json');

    expect(body).to.contain(relativeEscapeError);
    expect(body).not.to.contain('Test env');
  });

  it('should emit a route serving error when a path traversal is detected', () => {
    const code = ServerErrorCodes.ROUTE_SERVING_ERROR;
    const traversalErrors = errors.filter((error) => error.includes('Access'));
    const rootErrors = errors.filter((error) => error.includes(rootBaseError));

    expect(traversalErrors.length).to.equal(6);
    traversalErrors.forEach((error) => {
      expect(error.startsWith(`${code}: Access to`)).to.equal(true);
    });
    expect(rootErrors.length).to.equal(1);
    expect(rootErrors[0].startsWith(`${code}: Templated`)).to.equal(true);
  });
});
