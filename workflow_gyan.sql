4a0030398000010a
4a0030398000010a

1b00303980000d42 user1
1b00303980000d43 user2

//Activity Transition Types

	 * 0   Prescribed - package is forwarded to all output ports
     * 1   Manual - activity performers choose the output ports
     * 2   Automatic 

//Fetch Master workItem for Pseudo 
select * from dmi_workitem where r_workflow_id = '4d00303980000103' and r_act_def_id = '4c0030398000e0bf' and r_performer_name = 'd2_pseudo_user' order by r_creation_date desc

//Query to Fetch all workflows whose tasks are struck at 
select witem.r_workflow_id, witem.r_object_id as work_item_id from dmi_workitem witem, dm_workflow wf where witem.r_performer_name like 'd2_pseudo_user%' and witem.r_workflow_id = wf.r_object_id and witem.r_runtime_state = 0 and wf.r_runtime_state = 1 and exists ( select stamp from dmi_queue_item qitem where qitem.item_id = witem.r_object_id and qitem.name like 'd2_pseudo_user%') and not exists ( select stamp from dmi_queue_item qitem1 where qitem1.item_id = witem.r_object_id and qitem1.task_type = 'D2_PSEUDO')

//Include object details
SELECT DISTINCT witem.r_workflow_id, witem.r_object_id as work_item_id, witem.r_act_seqno, witem.r_act_def_id as activity_id, dc.r_object_id as document_id, dc.object_name from dmi_workitem witem, dm_workflow wf, dmi_package pkg, dm_document dc where witem.r_performer_name = 'd2_pseudo_user' and witem.r_workflow_id = wf.r_object_id and witem.r_runtime_state = 0 and wf.r_runtime_state = 1 and pkg.r_workflow_id = witem.r_workflow_id and any pkg.r_component_id = dc.r_object_id and exists ( select stamp from dmi_queue_item qitem where qitem.item_id = witem.r_object_id and qitem.name = 'd2_pseudo_user') and not exists ( select stamp from dmi_queue_item qitem1 where qitem1.item_id = witem.r_object_id and qitem1.task_type = 'D2_PSEUDO')

step-2 Run the below DQL to find the performer alias for the struck activity 
       select performer_name from dm_activity where r_object_id = <activity_id>

step-3 Find the list of Actual Performers for this activity from the workflow Tracker file
       DQL to fethc Tracker object
       select parent_id as tracker_id from dm_relation where child_id = '<workflow_id>' and relation_name = 'D2_WF_TRACKER_WORKFLOW'
       getfile,c,<tracker_id>
 	   Find the corresponding performer alias node in the tracker xml file which contains the list of actual users
	   Example :
	   <alias input="list" name="<performer_name>">
			<value>user_1</value>
			<value>user_2</value>
		</alias>

 step-4 : For each user run the below queue API to create task for the struck activity          
          queue,c,<work_item_id>,<user_name>,d2_startedpseudoworkitem,0,T,<due_date>,D2_PSEUDO
		  
		  Example : queue,c,4a00303980001d1e,testvikas2,d2_startedpseudoworkitem,0,T,,D2_PSEUDO 
		  
 Step-5: Verifcation step 
         Now you should see the tasks got created for each user in dmi_queue_item table.  
         select * from dmi_queue_item where item_id = '<work_item_id>' 
		 Verify the tasks are added to D2_PSEUDO_QUEUE_ITEM 
		 select * from dm_relation where relation_name = 'D2_PSEUDO_QUEUE_ITEM' and parent_id = '<work_item_id>'
            

step-1 //check workflow attributes r_act_state should be 1 and r_total_witem should be 0
  select r_act_state, r_total_witem from dm_workflow where r_object_id = '4d0030398000192b' and any r_act_def_id = '4c00303980019e6d'

step-2 // update r_total_witem to zero and r_act_state to 1 also update i_vstamp 
    update dm_workflow_r set r_total_witem = 0 where r_object_id = '<r_workflow_id of dmi_workitem>' and r_act_def_id = '<activity_definition_id>'
	update dm_workflow_r set r_act_state = 1 where r_object_id = '<r_workflow_id of dmi_workitem>' and r_act_def_id = '<activity_definition_id>'
    update dm_workflow_s set i_vstamp = <i_vstamp+1> where r_object_id = '<r_workflow_id of dmi_workitem>'
  
  sample :
		 execsql,c,update dm_workflow_r set r_act_state = 1 where r_object_id ='4d0030398000011f'
         execsql,c,update dm_workflow_r set r_total_witem = 0, i_vstamp=3 where r_object_id ='4d00303980000104'
		 execsql,c,update dm_workflow_s set i_vstamp = 4 where r_object_id ='4d0030398000011f'
 
 step-3 Fetch all the workItems belongs to the activity which is struck 
        select r_object_id from dmi_workitem where r_act_def_id = '4c003039800100b8' and r_workflow_id = '4d00303980000136'
 
 step-4
     Delete workitem object 
     delete dmi_workitem_s where r_object_id = '<r_object_id of dmi_workitem>' 
	 sample :
	         execsql,c,delete dmi_workitem_s where r_object_id in ( '4a0030398000010e')
			 execsql,c,delete dmi_workitem_r where r_object_id in ('4a0030398000010e')
			 execsql,c,delete dmi_queue_item_s where item_id in   ('4a0030398000010e')
 
 step-4 
     Recompute the workItem	
	 apply,c,NULL,RECOMPUTE_PERFORMER,WORKFLOW_ID,S,<workflow_id>,ACT_SEQNO,I,<r_act_seqno of deleted workitem id>
	 sample :
	    apply,c,NULL,RECOMPUTE_PERFORMER,WORKFLOW_ID,S,4d0030398000011f,ACT_SEQNO,I,1 
	 
              
delete dmi_queue_item objects where item_id = '4a0030398000010b' and task_type = 'D2_PSEUDO'

----------------------------------------------------------------------------------------------------------------------------------
Workflow Activity Transition Types
d2_wf_notification_user
transition_type integer S Specifies the type of the transition
condition. Valid values are:• 0: Prescribed. Packages are forwarded to output ports when the post-condition is met.
 							  1: Manual. Activity performers specify the output ports with the Setoutput method.
							  2: Automatic. Conditional routing
							  
							  
//Fetch audit of a workflow ID
select r_object_id,event_name,event_source,workflow_id,id_1,id_2,id_3,id_4,id_5  from dm_audittrail where workflow_id = '4d00303980000134' order by time_stamp_utc


//Fetch the list of events registered for the audit
 select distinct event,r_object_id,registered_id from dmi_registry
 
 //Register the following audit events for audit 
 dmc_completed_workflow                                            2600303980000500  0000000000000000
dm_all_workflow                                                   2600303980000501  0000000000000000
dm_startedworkitem                                                2600303980000502  0000000000000000
dm_delegatedworkitem                                              2600303980000503  0000000000000000
dm_changestateworkflow                                            2600303980000504  0000000000000000
dmc_completed_workitem                                            2600303980000505  0000000000000000
dm_changestateactivity                                            2600303980000506  0000000000000000
dm_completedworkitem                                              2600303980000507  0000000000000000

audit,c,4b00303980019e62,dm_all_workflow
audit,c,4d0030398000192b,dm_startedworkitem
audit,c,,dm_changestateactivity
audit,c,,dm_delegatedworkitem

unaudit,c,dm_save


 