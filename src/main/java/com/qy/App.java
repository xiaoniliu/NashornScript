package com.qy;

import java.io.FileReader;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory;
import org.openjdk.nashorn.api.scripting.ScriptObjectMirror;

public class App {

    public static String executeJs() throws Exception {
        NashornScriptEngineFactory nScriptEngineFactory = new NashornScriptEngineFactory();
        ScriptEngineManager scriptEngineManager = new ScriptEngineManager();
        // JDK11弃用NashornScript 需要手动注册
        // https://baijiahao.baidu.com/s?id=1610939313465715670&wfr=spider&for=pc
        scriptEngineManager.registerEngineName("test", nScriptEngineFactory);
        ScriptEngine engine = scriptEngineManager.getEngineByName("JavaScript");
        engine.eval(new FileReader("src/main/resources/utils/bn.js"));
        engine.eval(new FileReader("src/main/resources/utils/crypto.js"));
        engine.eval(new FileReader("src/main/resources/utils/index.js"));
        engine.eval(new FileReader("src/main/resources/utils/util.js"));
        Invocable inv = (Invocable) engine;
        ScriptObjectMirror result = (ScriptObjectMirror) inv.invokeFunction("getPubkey");
        System.out.println(result.entrySet());
        // for (Map.Entry<String, Object> item : result.entrySet()) {
        // System.out.println(item.getValue());
        // }
        return null;
    }

    public static void main(String[] args) throws Exception {
        executeJs();
    }

}