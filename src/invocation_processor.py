import logging
import pickle
import typing as t

from src.error import Error
from src.recorded_invocation import RecordedInvocation
from src.smali_invocation import SmaliInvocation
from src.smali_parser import SmaliParser


class InvocationProcessor:
    def pickle_invocations(self,
                           recorded_invocations: t.List[RecordedInvocation],
                           out_pickle_path: str):
        logging.info('Pickling invocations in [%s]...', out_pickle_path)
        pickle.dump(recorded_invocations,
                    open(out_pickle_path, 'wb'))

    def __cross_match_recorded_inv_with_smali_tree(self,
                                                   smali_parser: SmaliParser,
                                                   recorded_inv: RecordedInvocation
                                                   ) -> t.Tuple[t.Optional[SmaliInvocation],
                                                                t.Optional[Error]]:
        caller_clazz: str = recorded_inv.caller_info.clazz
        caller_method: str = recorded_inv.caller_info.method
        caller_linenum: int = recorded_inv.caller_info.linenum

        if caller_clazz not in smali_parser.classes:
            return(None,
                   Error(
                       'class [{}] not found. Possibly packed classloader'.format(caller_clazz)))

        arr = [inv
               for smali_method in smali_parser.classes[caller_clazz].methods
               if smali_method.name == caller_method

               for linenum, smali_line in smali_method.lines.items()
               if linenum == caller_linenum

               for inv in smali_line.block
               if isinstance(inv, SmaliInvocation)
               and inv.method_sig == recorded_inv.method_sig
               ]

        if not arr:
            return None, None

        return arr[0], None

    def annotate_smali_tree(self,
                            recorded_invocations: t.List[RecordedInvocation],
                            smali_parser: SmaliParser):
        """
        Process [recorded_invocations] in order to annotate the smali tree, located in
          [smali_parser].
        """
        for recorded_inv in recorded_invocations:
            smali_invocation, err = self.__cross_match_recorded_inv_with_smali_tree(
                smali_parser,
                recorded_inv)

            if err:
                # Don't fail. Continue processing
                logging.error(err)
                continue
            if not smali_invocation:
                # Don't fail. Continue processing
                logging.error(
                    'Could not recorded invocation in the smali tree: %s',
                    recorded_inv.__dict__)
                continue

            smali_invocation.add_annotation(recorded_inv.describe())
            recorded_inv.did_annotate = True
