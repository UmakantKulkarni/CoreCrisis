import json
from objects.oracle import Oracle
from objects.power_schedule import Seed
from fsm_helper import get_trace_from_path

# path class in state
class Path:
    def __init__(self, path_states: list, input_symbols: list, output_symbols: list):
        self.path_states = path_states
        self.input_symbols = input_symbols
        self.output_symbols = output_symbols
        self.count = 0
    
    @classmethod
    def from_json(cls, path_states: list, input_symbols: list, output_symbols: list, count: int):
        new_path = cls(path_states, input_symbols, output_symbols)
        new_path.count = count
        return new_path

    def add_count(self):
        self.count += 1

# state class in FSM
class State(Seed):
    def __init__(self, name: str, paths: list):
        super().__init__()
        self.name = name
        self.paths = paths
        self.is_init = False
        self.oracle = Oracle()

    @classmethod
    def from_json(cls, energy: float, adjusted_energy: float, count: int, name: str, paths: list, is_init: bool, p_state: str):
        new_state = cls(name, paths)
        new_state.energy = energy
        new_state.adjusted_energy = adjusted_energy
        new_state.count = count
        new_state.is_init = is_init
        new_state.oracle.state = p_state
        return new_state
    
    def add_path(self, path):
        self.paths.append(path)

    def is_existed_path(self, new_path):
        for existed_path in self.paths:
            if existed_path.path_states == new_path:
                return True
        return False

    def select_path(self):
        if self.paths == []:
            return None
        selected_path = self.paths[0]
        if selected_path.count > 50:
            for path in self.paths:
                if path.count < selected_path.count:
                    selected_path = path
        selected_path.add_count()
        self.count += 1
        return selected_path

# FSM class
class FSM:
    def __init__(self, states: list, init_state: str, transitions: list):
        self.states = states
        self.init_state = init_state
        self.transitions = transitions
        self.new_state_conut = 0

    def add_new_state(self):
        new_state = State("H"+str(self.new_state_conut), [])
        self.new_state_conut += 1
        self.states.append(new_state)
        return new_state

    def search_transition(self, start_state: str, input_sym: str, output_sym: str):
        for transition in self.transitions:
            if transition[0] == start_state and transition[1] == input_sym and transition[2] == output_sym:
                return True
        return False
    
    def search_new_transition(self, start_state: str, input_sym: str, output_sym: str):
        if self.search_transition(start_state, input_sym, output_sym):
            return True
        else:
            for transition in self.transitions:
                if ":" in transition[1]:
                    if transition[0] == start_state and input_sym in transition[1] and transition[2] == output_sym:
                        return True
        return False

    def get_state(self, name: str):
        for state in self.states:
            if state.name == name:
                return state
        return None
    
    def get_state_names(self):
        state_names = []
        for state in self.states:
            state_names.append(state.name)
        return state_names
    
    def refresh_paths(self):
        for state in self.states:
            for path in state.paths:
                path.input_symbols, path.output_symbols = get_trace_from_path(self, path.path_states)
                print("path.input_symbols:", path.input_symbols)
    
    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__, indent=4)
    
    @classmethod
    def from_json(cls, fsm_json):
        fsm_dict = json.loads(fsm_json)
        states = []
        for state in fsm_dict['states']:
            paths = []
            for path in state['paths']:
                paths.append(Path.from_json(path['path_states'], path['input_symbols'], path['output_symbols'], path['count']))
            states.append(State.from_json(state['energy'], state['adjusted_energy'], state['count'], state['name'], paths, state['is_init'], state['oracle']['state']))
        fsm = FSM(states, fsm_dict['init_state'], fsm_dict['transitions'])
        fsm.new_state_conut = fsm_dict['new_state_conut']
        return fsm
    