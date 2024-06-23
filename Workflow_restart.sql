//query to delete tasks 
delete dmi_queue_item objects where stamp in ( '1b00303980000e1c', '1b00303980000e1d', '1b00303980000e1e', '1b00303980000e1f' )

 execsql,c,update dm_workflow_r set r_act_state = 1 where r_object_id ='4d00303980000136'
 execsql,c,update dm_workflow_s set i_vstamp = 4 where r_object_id ='4d00303980000136'
 
 fetch,c,4d00303980000136
 
 apply,c,NULL,RECOMPUTE_PERFORMER,WORKFLOW_ID,S,4d00303980000136,ACT_SEQNO,I,1

audit,c,dm_save

select r.registered_id, r.event,r.user_name from dmi_registry r where r.is_audittrail = 1



select q.stamp,q.item_id,w.r_act_def_id,q.router_id,q.task_state,q.name from dmi_queue_item q, dmi_workitem w where q.router_id = '4d00303980001932' and q.task_state <> 'finished' and q.item_id = w.r_object_id

//Query to fetch total audit of workflow
select r_object_id,event_name,event_source,workflow_id,id_1,id_2,id_3,id_4,id_5  from dm_audittrail where workflow_id = '4d00303980000132' order by time_stamp_utc

//Query to fetch queue items of workflow
select q.stamp,q.item_id,w.r_act_def_id,q.router_id,q.task_state,q.name from dmi_queue_item q, dmi_workitem w where q.router_id = '4d00303980000136' and q.task_state <> 'finished' and q.item_id = w.r_object_id order by w.r_act_def_id

-----------------------------------------------------------------------------------------------------------------------------------
   select r_act_state, r_total_witem from dm_workflow_r where r_object_id = '4d00303980000136' and r_act_def_id = '4c003039800100b8'


execsql,c,update dm_workflow_r set r_total_witem = 0 where r_object_id = '4d00303980000136' and r_act_def_id = '4c003039800100b8'
execsql,c,update dm_workflow_r set r_act_state = 1 where r_object_id = '4d00303980000136' and r_act_def_id = '4c003039800100b8'
execsql,c,update dm_workflow_s set i_vstamp = i_vstamp + 1 where r_object_id = '4d00303980000136'

 execsql,c,delete dmi_queue_item_s where item_id in (select r_object_id from dmi_workitem_s where r_act_def_id = '4c003039800100b8' and r_workflow_id = '4d00303980000136')
 execsql,c,delete dmi_workitem_s where r_object_id in (select r_object_id from dmi_workitem_s where r_act_def_id = '4c003039800100b8' and r_workflow_id = '4d00303980000136')
 execsql,c,delete dmi_workitem_r where r_object_id in (select r_object_id from dmi_workitem_s where r_act_def_id = '4c003039800100b8' and r_workflow_id = '4d00303980000136')
 
 
 apply,c,NULL,RECOMPUTE_PERFORMER,WORKFLOW_ID,S,4d00303980000136,ACT_SEQNO,I,1 
 
 //Deleting queue items before invoking Queue API
 delete dm_relation objects where relation_name = 'D2_PSEUDO_QUEUE_ITEM' and parent_id = '4a00303980001d1e'
 delete dmi_queue_item objects where item_id = '4a00303980001d1e' and task_type = 'D2_PSEUDO'
 
 //send notification using queue API
 queue,c,4a00303980001d1e,testvikas1,d2_startedpseudoworkitem,0,T,,D2_PSEUDO
 
 getmessage,c,