'use strict';

import Java from '../frida-java-bridge/index.js';

const state = {
  nativeHits: 0,
  openatHits: 0,
  javaHits: 0,
  heartbeats: 0,
  packageName: '',
  javaReady: false
};

const listeners = [];

function installNativeProbe(name, counter) {
  const libc = Process.getModuleByName('libc.so');
  const address = libc.getExportByName(name);
  listeners.push(Interceptor.attach(address, {
    onEnter() {
      state[counter] += 1;
    }
  }));
  return address;
}

const getpidAddress = installNativeProbe('getpid', 'nativeHits');
const openatAddress = installNativeProbe('openat', 'openatHits');
const getpid = new NativeFunction(getpidAddress, 'int', []);

send({
  kind: 'native-ready',
  pid: Process.id,
  getpid: getpidAddress.toString(),
  openat: openatAddress.toString()
});

Java.perform(function () {
  try {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const ContextWrapper = Java.use('android.content.ContextWrapper');
    const getPackageName = ContextWrapper.getPackageName.overload();
    getPackageName.implementation = function () {
      state.javaHits += 1;
      return getPackageName.call(this);
    };
    const app = ActivityThread.currentApplication();
    if (app !== null) {
      state.packageName = String(app.getPackageName());
    }
    state.javaReady = true;
    send({kind: 'java-ready', packageName: state.packageName});
  } catch (error) {
    send({kind: 'java-error', message: String(error)});
  }
});

const timer = setInterval(function () {
  const pid = getpid();
  state.heartbeats += 1;
  send({
    kind: 'heartbeat',
    pid: pid,
    sequence: state.heartbeats,
    nativeHits: state.nativeHits,
    openatHits: state.openatHits,
    javaHits: state.javaHits,
    javaReady: state.javaReady,
    packageName: state.packageName
  });
}, 1000);

rpc.exports = {
  snapshot() {
    return Object.assign({}, state, {pid: Process.id});
  },
  dispose() {
    clearInterval(timer);
    listeners.forEach(function (listener) {
      listener.detach();
    });
    return Object.assign({}, state, {pid: Process.id});
  }
};
