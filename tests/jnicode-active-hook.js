'use strict';

import Java from '../frida-java-bridge/index.js';

// Visible, test-only Frida oracle for the user's debuggable JNICode APK.
// It changes the JNI-bound method's return and onCreate's final UI state.
Java.perform(function () {
  const MainActivity = Java.use('com.laodeng.jnicode.MainActivity');
  const ResourceIds = Java.use('com.laodeng.jnicode.R$id');
  const TextView = Java.use('android.widget.TextView');
  const JavaString = Java.use('java.lang.String');
  const stringFromJNI = MainActivity.stringFromJNI.overload();
  const onCreate = MainActivity.onCreate.overload('android.os.Bundle');

  stringFromJNI.implementation = function () {
    const original = stringFromJNI.call(this);
    const replacement = 'Hooked from JNI';
    send({kind: 'native', original: String(original), replacement: replacement});
    return replacement;
  };

  onCreate.implementation = function (savedInstanceState) {
    onCreate.call(this, savedInstanceState);
    const view = this.findViewById(ResourceIds.sample_text.value);
    if (view === null) {
      throw new Error('sample_text view is absent after onCreate');
    }
    const textView = Java.cast(view, TextView);
    const before = textView.getText().toString();
    const replacement = 'Hooked by onCreate';
    textView.setText.overload('java.lang.CharSequence').call(
      textView, JavaString.$new(replacement));
    send({kind: 'onCreate', before: before,
          after: textView.getText().toString()});
  };
});
