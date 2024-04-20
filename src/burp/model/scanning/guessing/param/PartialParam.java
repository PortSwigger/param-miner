package burp.model.scanning.guessing.param;

import burp.IParameter;

public class PartialParam implements IParameter {

    private int valueStart, valueEnd;
    private String name;
    private byte type;

    public PartialParam(String name, int valueStart, int valueEnd) {
        this(name, valueStart, valueEnd, IParameter.PARAM_COOKIE);
    }

    public PartialParam(String name, int valueStart, int valueEnd, byte type) {
        this.name = name;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
        this.type = type;
    }



    @Override
    public byte getType() {
        return type;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return null;
    }

    @Override
    public int getNameStart() {
        return 0;
    }

    @Override
    public int getNameEnd() {
        return 0;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }
}

