from saft_msgs.srv import RunPipeline
from rcl_interfaces.msg import Parameter
from rcl_interfaces.msg import ParameterType

import rclpy
from rclpy.node import Node

import subprocess
import os
import json
import requests
import re
import glob
import time

from . import saft_config as cfg

class SaftPipeline(Node):
    def __init__(self):
        self.timer = -1
        super().__init__('saft_pipeline')
        
        # initialize run_pipeline service
        self.srv = self.create_service(RunPipeline, 'run_pipeline', self.run_pipeline_callback)

        # initialize publisher to write to knowledge base
        # the hardcoded topic /kb_change is used by the
        # model_checker_feedback_monitor in the mape_k system
        self.kb_pub = self.create_publisher(Parameter, '/kb_change', 10)

        # timer to run the pipline every hour
        # self.timer = self.create_timer(3600, lambda : self.run_pipeline(RunPipeline.Request.ALL))

    def run_pipeline_callback(self, request, response):
        self.timer = time.perf_counter()
        self.get_logger().info(f'start time: {self.timer} s')

        # We do some elementary checks, if the request is valid. 
        requests_names = ["CLEAN_ALL_DATA",
                          "CREATE_DATAFLOW_MODEL",
                          "FETCH_DATAFLOW_MODEL",
                          "COMBINE_DATAFLOW_MODELS",
                          "CLEANUP_DATAFLOW_MODEL",
                          "CREATE_DEPLOYMENT_MODEL",
                          "ENHANCE_DEPLOYMENT_MODEL",
                          "EXTRACT_PACKAGES_FILES",
                          "CREATE_INPUT_FOR_ATG",
                          "ATTACK_GEN_CPE",
                          "ATTACK_GEN_FILES",
                          "AFT_COMBINATION",
                          "AFT_TO_DFT",
                          "RUN_MC",]
        if request.stages_to_run < 0 or request.stages_to_run > 2**len(requests_names)-1:
            response.run_accepted = False
            response.error_msg = 'Invalid stage bitmask'
            return response
        
        def number_to_bits_array(number,length):
            # Convert the number to its binary representation and remove the '0b' prefix
            binary_string = bin(number)[2:]

            # Pad the binary string with leading zeros if necessary to ensure it has 8 bits
            padded_binary_string = binary_string.zfill(length)  # Adjust the parameter (8) for different bit lengths

            # Convert the padded binary string to a list of integers (0s and 1s)
            bits_array = [int(bit) for bit in padded_binary_string]

            return bits_array
        
        def convert_bits_to_strings(bit_constants, array):
            result = ""
            for i in range(len(bit_constants)):
                if array[i] == 1:
                    result += bit_constants[i] + ", "
            if len(result) > 0:
                result = result[:-2]
            return result

        bit_array = list(reversed(number_to_bits_array(request.stages_to_run,len(requests_names))))
        self.get_logger().info('Pipeline run requested for stages ' \
                               + convert_bits_to_strings(requests_names, bit_array))

        # the pipeline run is wrapped in a timer callback to be able to send the
        # response before the node is blocked while the pipeline executes.
        # the timer is destroyed immediately to avoid executing the pipeline multiple times
        oneshot_timer = self.create_timer(0.1,
            lambda : self.run_pipeline(request.stages_to_run) or oneshot_timer.cancel())

        response.run_accepted = True
        response.error_msg = ''

        return response
    
    def run_pipeline(self, stages):
        self.get_logger().info('Pipeline started')
        
        if stages & RunPipeline.Request.CLEAN_ALL_DATA:
            pass
            # commented out for debugging purposes
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP CLEAN_ALL_DATA: Clean all temporary data")
            try:
                for f in cfg.list_of_temp_files:
                    os.remove(f)
            except OSError:
                pass  # intentionally ignore the exceptions
            if os.path.exists(cfg.ATs_outputpath):
                for f in glob.glob(os.path.join(cfg.ATs_outputpath,'*')):
                    os.remove(f)
            else:
                os.mkdir(cfg.ATs_outputpath)
            self.log_duration(RunPipeline.Request.CLEAN_ALL_DATA)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.CREATE_DATAFLOW_MODEL:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP CREATE_DATAFLOW_MODEL: Trigger creation of (partial) dataflow model from (other) ROS system")
            self.get_logger().info("using ssh port: "+cfg.port+" at "+cfg.username+"@"+cfg.hostname)
            output = subprocess.run(["ssh","-p "+cfg.port,cfg.username+"@"+cfg.hostname,"source_ros2 && ros2 service call /saft/get_dataflow std_srvs/Trigger"],capture_output=True)
            #TODO: port and access information via parameter? 
            self.log_duration(RunPipeline.Request.CREATE_DATAFLOW_MODEL)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.FETCH_DATAFLOW_MODEL:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP FETCH_DATAFLOW_MODEL: Fetch automatically created ros dataflow model from remote server")
            self.get_logger().info("using ssh port: "+cfg.port+" at "+cfg.username+"@"+cfg.hostname+":~/ros2_ws/"+cfg.name_of_ros_dataflow_model)
            self.get_logger().info("writing file to: "+cfg.models_path)
            self.get_logger().info("credentials must be provided by public keys")
            subprocess.run(["scp","-P"+cfg.port,cfg.username+"@"+cfg.hostname+":~/ros2_ws/"+cfg.name_of_ros_dataflow_model,cfg.models_path])
            #TODO: port and access information via parameter?
            self.log_duration(RunPipeline.Request.FETCH_DATAFLOW_MODEL)
#            self.get_logger().info(f'elapsed time [s]: {(time.perf_counter()-self.timer)}')
            self.get_logger().info("== Finished =============================================================")
        
        if stages & RunPipeline.Request.COMBINE_DATAFLOW_MODELS:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP COMBINE_DATAFLOW_MODELS: Combine generated and manual dataflow models")
            self.get_logger().info("combining the following files: "+str(cfg.names_of_dataflow_models))
            self.get_logger().info("into: "+cfg.name_of_combined_dataflow_model)
            dataflow_file = open(cfg.name_of_combined_dataflow_model,"w")
            for file in cfg.names_of_dataflow_models:
                input_file = open(file,"r")
                dataflow_file.write(input_file.read())
                input_file.close()
            dataflow_file.close()
            self.log_duration(RunPipeline.Request.COMBINE_DATAFLOW_MODELS)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.CLEANUP_DATAFLOW_MODEL:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP CLEANUP_DATAFLOW_MODEL: Cleanup dataflow model (remove unconnected channels)")
            self.get_logger().info("cleaning up: "+cfg.name_of_combined_dataflow_model)
            subprocess.run(["java", "-jar", os.path.join(cfg.tools_path,"data2deploy.jar"), "--clean", cfg.name_of_combined_dataflow_model, cfg.name_of_combined_dataflow_model])
            self.log_duration(RunPipeline.Request.CLEANUP_DATAFLOW_MODEL)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.CREATE_DEPLOYMENT_MODEL:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP CREATE_DEPLOYMENT_MODEL: Create (initial) deployment model from dataflow models")
            self.get_logger().info("creating: "+cfg.name_of_ros_deployment_model)
            self.get_logger().info("using: "+cfg.name_of_combined_dataflow_model)
            subprocess.run(["java", "-jar", os.path.join(cfg.tools_path,"data2deploy.jar"), cfg.name_of_combined_dataflow_model, cfg.name_of_ros_deployment_model])
            self.log_duration(RunPipeline.Request.CREATE_DEPLOYMENT_MODEL)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.ENHANCE_DEPLOYMENT_MODEL:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP ENHANCE_DEPLOYMENT_MODEL: Enhance inital deployment models with dependencies ")
            self.get_logger().info("creating: "+cfg.name_of_deployment_enhanced_model)
            self.get_logger().info("using: "+cfg.name_of_ros_deployment_model+" and "+cfg.name_of_manual_deployment_model)
            deployment_enhanced = open(cfg.name_of_deployment_enhanced_model,"w")
            subprocess.run([os.path.join(cfg.tools_path,"dependency_explorer"),"scan",cfg.name_of_ros_deployment_model, cfg.name_of_manual_deployment_model], stdout=deployment_enhanced)
            deployment_enhanced.close()
            self.log_duration(RunPipeline.Request.ENHANCE_DEPLOYMENT_MODEL)
            self.get_logger().info("== Finished =============================================================")


        if stages & RunPipeline.Request.EXTRACT_PACKAGES_FILES:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP EXTRACT_PACKAGE_FILES: Extract packages and files from enhanced deployment model ")
            self.get_logger().info("creating: "+cfg.name_of_packages_file+" and "+cfg.name_of_files_file)
            self.get_logger().info("using: "+cfg.name_of_deployment_enhanced_model)
            packages_file = open(cfg.name_of_packages_file,"w")
            subprocess.run([os.path.join(cfg.tools_path,"dependency_explorer"),"pkgs",cfg.name_of_deployment_enhanced_model], stdout=packages_file)
            packages_file.close()
            files_file = open(cfg.name_of_files_file,"w")
            subprocess.run([os.path.join(cfg.tools_path,"dependency_explorer"),"files",cfg.name_of_deployment_enhanced_model], stdout=files_file)
            files_file.close()
            self.log_duration(RunPipeline.Request.EXTRACT_PACKAGES_FILES)
            self.get_logger().info("== Finished =============================================================")

        def apply_replacements(word):
            for replacement in cfg.replacements:
                word = word.replace(replacement,cfg.replacements[replacement])
            return word

        def remove_directories_and_file_endings(s):
            s = s.split('/')[-1]
            s = s[0:s.find('.so')]
            return s

        def  create_files(line):
            if line == None or len(line) == 0:
                return {}
            orig_line = line
            file_entry = dict()
            file_entry["id"] = remove_directories_and_file_endings(line)
            file_entry["synonyms"] = [orig_line]
            return file_entry

        def toId(varStr): return re.sub('\W','_', varStr)

        def simplify_version(version):
            return version.split('-')[0].split('+')[0]

        def create_cpes(line):
            if line == None or len(line) == 0:
                return (None,"")
            columns = line.split('\t')
            search_param = {"query": list(apply_replacements(columns[1]).split('_'))}
            response = requests.post(cfg.url_of_cpesearch,json=search_param)
            response_json = response.json()
            if len(response_json) > 0:
                cpe = dict()
                cpe["id"] = response_json[0][1] +":"+simplify_version(columns[2])

                cpe["synonyms"] = [columns[1]] # ,toId(columns[0])+"__"+toId(columns[1])+"__"+toId(columns[2])+"__"+toId(columns[3])]
                return (True, cpe)
            else:
                result = dict()
                result["id"] = columns[1]
                result["synonyms"] = [columns[1]]
                return (False, result)

        if stages & RunPipeline.Request.CREATE_INPUT_FOR_ATG:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP CREATE_INPUT_FOR_ATG: Create input file for AT generation ")
            self.get_logger().info("creating: "+cfg.name_of_at_cpesearch+" and "+cfg.name_of_at_fullsearch)
            self.get_logger().info("using: "+cfg.name_of_packages_file+" and "+cfg.name_of_files_file)
            # full text search for files, CPE creation for packages
            packages_file = open(cfg.name_of_packages_file,"r")
            at_cpesearch = open(cfg.name_of_at_cpesearch,"w") 
            lines = packages_file.read().split('\n')
            cpes = list()
            fulltext_search = list()
            for line in lines:
                result, content = create_cpes(line)
                if result == True:
                    cpes.append(content)
                else:
                    if result == False:
                        fulltext_search.append(content)    # save package information if no cpe was found
                    # else:
                        # intentionally do nothing
            json_array = json.dumps(list(cpes),indent=4)
            at_cpesearch.write(json_array)
            at_cpesearch.close()
            packages_file.close()   

            files_file = open(cfg.name_of_files_file,"r")
            at_fullsearch = open(cfg.name_of_at_fullsearch,"w")
            lines = files_file.read().split('\n')
            lines = list(map(create_files, lines))
            lines = lines + fulltext_search        # add packages for which no cpe was found
            json_array = json.dumps(list(filter(None, lines)),indent=4)
            at_fullsearch.write(json_array)
            at_fullsearch.close()
            files_file.close()
            self.log_duration(RunPipeline.Request.CREATE_INPUT_FOR_ATG)
            self.get_logger().info("== Finished =============================================================")


        if stages & RunPipeline.Request.ATTACK_GEN_CPE:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP ATTACK_GEN_CPE: Call AT generator with CPE list")
            self.get_logger().info("creating Attackgraphs in: "+cfg.ATs_outputpath)
            self.get_logger().info("using: "+cfg.name_of_at_cpesearch)
            curr_path = os.path.abspath(os.path.curdir)
            os.chdir(cfg.path_to_AT_generator)
            subprocess.run(["./generate.py","-fp",os.path.join(curr_path,cfg.name_of_at_cpesearch),os.path.join(curr_path,cfg.ATs_outputpath)]) 
            os.chdir(curr_path)
            self.log_duration(RunPipeline.Request.ATTACK_GEN_CPE)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.ATTACK_GEN_FILES:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP ATTACK_GEN_FILES: Call AT generator with file list (for full text search)")
            self.get_logger().info("creating Attackgraphs in: "+cfg.ATs_outputpath)
            self.get_logger().info("using: "+cfg.name_of_at_fullsearch)
            curr_path = os.path.abspath(os.path.curdir)
            os.chdir(cfg.path_to_AT_generator)
            subprocess.run(["./generate.py","-fs",os.path.join(curr_path,cfg.name_of_at_fullsearch),os.path.join(curr_path,cfg.ATs_outputpath)]) 
            os.chdir(curr_path)
            self.log_duration(RunPipeline.Request.ATTACK_GEN_FILES)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.AFT_COMBINATION:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP AFT_COMBINATION: Call AFT generator with all created models")
            self.get_logger().info("Creating AFT for "+cfg.name_of_fault_tree)
            self.get_logger().info("using: "+cfg.name_of_combined_dataflow_model+" and "+cfg.name_of_deployment_enhanced_model)
            self.get_logger().info("writing the result into "+cfg.name_of_attack_fault_tree)
            # remove paths from the files because the project path is already added internally
            subprocess.run(["java", "-jar", os.path.join(cfg.tools_path,"AFTGenerator.jar"), cfg.models_path+"/", os.path.basename(cfg.name_of_fault_tree), os.path.basename(cfg.name_of_combined_dataflow_model), os.path.basename(cfg.name_of_deployment_enhanced_model), "eval"])
            # outputfile is: generatedAFTTextFile.attackFaultTree
            self.log_duration(RunPipeline.Request.AFT_COMBINATION)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.AFT_TO_DFT:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP AFT_TO_DFT: Convert AFT to DFT in Galileo input format ")
            self.get_logger().info("Creating Galileo-DFT for "+cfg.name_of_attack_fault_tree+ " and writing the result into "+cfg.name_of_dft)
            subprocess.run(["java", "-jar", os.path.join(cfg.tools_path,"aft2dft.jar"), cfg.name_of_attack_fault_tree, cfg.dft_file])
            self.log_duration(RunPipeline.Request.AFT_TO_DFT)
            self.get_logger().info("== Finished =============================================================")

        if stages & RunPipeline.Request.RUN_MC:
            self.get_logger().info("=========================================================================")
            self.get_logger().info("STEP RUN_MC: Run STORM model checker with DFT as input ")
            self.get_logger().info("Check for storm docker container with name: "+cfg.storm_docker_container_name)
            # dot_file = os.path.join(cfg.storm_docker_data_path,"state_tree.dot")
            result = subprocess.run(["sudo", "docker", "container", "inspect", cfg.storm_docker_container_name],capture_output=True)
            if (result.returncode != 0):
                self.get_logger().info("docker container for storm not running!")
            else:
                self.get_logger().info("docker container for storm is running!")
                subprocess.run(["docker", "cp", cfg.dft_file, cfg.storm_docker_container_name+":/"])                
                result = subprocess.run(["docker", "exec", cfg.storm_docker_container_name, 
                                        "storm-dft","-dft","/"+cfg.name_of_dft,"-mttf","--dft-statistics","--relevantevents","all"],capture_output=True)
                if (result.returncode != 0):
                    self.get_logger().info("storm model checker failed!")
                    self.get_logger().info("stderr: "+str(result.stderr))
                    self.get_logger().info("stdout: "+str(result.stdout))
                    storm_result = ""
                else:
                    storm_result = str(result.stdout.splitlines()[-1])

                try:
                    mttf_match = re.match('.*\[(.*)\]',storm_result).group(1)
                    mttf = float(mttf_match)
                except (ValueError, AttributeError):
                    self.get_logger().info("Cannot extract result from string returned by storm model checker: "+storm_result)
                    mttf = -1.0

                self.get_logger().info(str(mttf))
                # self.get_logger().info(dot_file)
      
                # Write result back to knowledge base
                msg = Parameter()
                msg.name = 'mttf'
                msg.value.type = ParameterType.PARAMETER_DOUBLE
                msg.value.double_value = mttf
                self.kb_pub.publish(msg)
            self.log_duration(RunPipeline.Request.RUN_MC)
            self.get_logger().info("== Finished =============================================================")                

    def log_duration(self,stage):
        duration = time.perf_counter()-self.timer
        with open("perf_measurements.csv",'a') as perf_file:
            perf_file.write(f'step {stage},{duration},{time.strftime("%H:%M:%S",time.localtime())}\n')



def load_replacements():
    replacement_file = open(cfg.name_of_replacement_file,"r")
    lines = replacement_file.read().split('\n')
    for line in lines:
        definition = line.split("=")
        cfg.replacements[definition[0]] = definition[1]
    replacement_file.close()


def main(args=None):
    load_replacements()
    rclpy.init(args=args)

    pipeline = SaftPipeline()
    rclpy.spin(pipeline) # run the pipline node event loop
    rclpy.shutdown()

if __name__ == '__main__':
    main()
