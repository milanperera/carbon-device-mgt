package org.wso2.carbon.device.application.mgt.core.lifecycle;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class LifecycleStateManger {

    private Map<String, State> lifecycleStates;

    public LifecycleStateManger(List<State> states) {
        lifecycleStates = new HashMap<>();
        for (State s : states) {
            lifecycleStates.put(s.getState(), s);
        }
    }

    public Set<String> getNextLifecycleStates(String currentLifecycleState) {
        return lifecycleStates.get(currentLifecycleState).getProceedingStates();
    }

    public boolean isValidStateChange(String currentState, String nextState) {
        if (lifecycleStates.get(currentState).getProceedingStates().contains(nextState)) {
            return true;
        }
        return false;
    }
}
